package confidential.statemanagement.privatestate.sender;

import bftsmart.reconfiguration.ServerViewController;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.utils.HashThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public abstract class BlindedStateSender extends Thread {
    protected final Logger logger = LoggerFactory.getLogger("state_transfer");
    private final ServerViewController svController;
    private final int pid;
    private final byte[] commonState;
    private final LinkedList<Share> shares;
    private final LinkedList<Commitment> commitments;
    private final int blindedStateReceiverPort;
    protected final ServerConfidentialityScheme confidentialityScheme;
    private final boolean iAmStateSender;
    private VerifiableShare[] blindingShares;
    protected final int[] blindedStateReceivers;
    private final Lock lock;
    private final Condition waitingBlindingSharesCondition;
    private BlindedDataSender[] stateSenders;

    public BlindedStateSender(ServerViewController svController, byte[] commonState, LinkedList<Share> shares,
                              LinkedList<Commitment> commitments, int blindedStateReceiverPort,
                              ServerConfidentialityScheme confidentialityScheme,
                              boolean iAmStateSender,
                              int... blindedStateReceivers) {
        super("Blinded State Sender Thread");
        this.svController = svController;
        this.pid = svController.getStaticConf().getProcessId();
        this.commonState = commonState;
        this.shares = shares;
        this.commitments = commitments;
        this.blindedStateReceiverPort = blindedStateReceiverPort;
        this.confidentialityScheme = confidentialityScheme;
        this.iAmStateSender = iAmStateSender;
        this.blindedStateReceivers = blindedStateReceivers;
        this.lock = new ReentrantLock(true);
        this.waitingBlindingSharesCondition = lock.newCondition();
    }

    @Override
    public void interrupt() {
        for (BlindedDataSender stateSender : stateSenders) {
            stateSender.shutdown();
            stateSender.interrupt();
        }
        super.interrupt();
    }

    public void setBlindingShares(VerifiableShare[] blindingShares) {
        lock.lock();
        this.blindingShares = blindingShares;
        waitingBlindingSharesCondition.signal();
        lock.unlock();
    }

    @Override
    public void run() {
        logger.debug("Generating Blinded State");
        try {
            long t1, t2, totalElapsed = 0;
            stateSenders = new BlindedDataSender[blindedStateReceivers.length];
            for (int i = 0; i < blindedStateReceivers.length; i++) {
                int blindedStateReceiver = blindedStateReceivers[i];
                String receiverIp = svController.getCurrentView().getAddress(blindedStateReceiver)
                        .getAddress().getHostAddress();
                int port = blindedStateReceiverPort + blindedStateReceiver;
                BlindedDataSender stateSender = new BlindedDataSender(pid, receiverIp, port, iAmStateSender);
                stateSender.start();
                stateSenders[i] = stateSender;
            }

            HashThread commonStateHashThread = null;
            if (iAmStateSender) {
                for (BlindedDataSender stateSender : stateSenders) {
                    stateSender.setCommonState(commonState, null);
                }
            } else {
                commonStateHashThread = new HashThread();
                commonStateHashThread.setData(commonState);
                commonStateHashThread.start();
                commonStateHashThread.update(0, commonState.length);
                commonStateHashThread.update(-1, -1);
            }
            lock.lock();
            try {
                if (blindingShares == null)
                    waitingBlindingSharesCondition.await();
            } catch (InterruptedException e) {
                return;
            } finally {
                lock.unlock();
            }

            logger.debug("Received blinding shares");

            if (commonStateHashThread != null) {
                byte[] commonStateHash = commonStateHashThread.getHash();
                for (BlindedDataSender stateSender : stateSenders) {
                    stateSender.setCommonState(null, commonStateHash);
                }
            }

            t1 = System.nanoTime();
            BlindedShares blindedShares = computeBlindedShares(shares, commitments, blindingShares);
            t2 = System.nanoTime();
            blindingShares = null;
            totalElapsed += t2 - t1;
            double total = totalElapsed / 1_000_000.0;
            if (blindedShares == null) {
                logger.error("Blinded shares are null. Exiting blinded state sender thread.");
                return;
            }
            logger.info("Took {} ms to compute blinded shares [{} shares]", total, blindedShares.getShare().length);

            for (BlindedDataSender stateSender : stateSenders) {
                stateSender.setBlindedShares(blindedShares);
            }

        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to create hash thread.", e);
        }

        logger.debug("Existing blinded state sender thread");
    }

    protected abstract BlindedShares computeBlindedShares(LinkedList<Share> shares, LinkedList<Commitment> commitments,
                                                            VerifiableShare[] blindingShares);
}
