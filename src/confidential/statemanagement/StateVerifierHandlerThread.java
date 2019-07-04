package confidential.statemanagement;

import bftsmart.tom.server.defaultservices.CommandsInfo;
import confidential.ConfidentialData;
import confidential.server.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.CommitmentScheme;
import vss.commitment.Commitments;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

public class StateVerifierHandlerThread extends Thread {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private BlockingQueue<RecoverySMMessage> recoveryMessages;
    private VerificationCompleted listener;
    private CommitmentScheme commitmentScheme;
    private final int quorum;
    private AtomicInteger validStates;
    private ExecutorService executor;
    private Thread thisThread;
    private Set<BigInteger> shareholdersBlackList;

    public StateVerifierHandlerThread(VerificationCompleted listener, int f, CommitmentScheme commitmentScheme) {
        super("State Verifier Thread");
        this.recoveryMessages = new LinkedBlockingQueue<>();
        this.listener = listener;
        this.commitmentScheme = commitmentScheme;
        this.quorum = f + 1;//TODO should be 2f + 1
        this.executor = Executors.newFixedThreadPool(quorum);
        this.validStates = new AtomicInteger(0);
        this.thisThread = this;
        this.shareholdersBlackList = new HashSet<>();
    }


    public void addStateForVerification(RecoverySMMessage recoveryMessage) {
        try {
            recoveryMessages.put(recoveryMessage);
        } catch (InterruptedException e) {
            logger.error("Failed to out state for verification from {}", recoveryMessage.getSender(), e);
        }
    }

    @Override
    public void run() {
        while (true) {
            try {
                RecoverySMMessage recoveryMessage = recoveryMessages.take();
                if (validStates.get() > quorum) {
                    logger.debug("I have already f + 1 valid states. Ignoring {}'s state", recoveryMessage.getSender());
                    break;
                }

                executor.submit(() -> {
                    boolean valid = isValidState((RecoveryApplicationState) recoveryMessage.getState());//TODO store deserialized state
                    if (valid)
                        validStates.incrementAndGet();

                    if (validStates.get() <= quorum)
                        listener.onVerificationCompleted(valid, recoveryMessage);
                    if (validStates.get() > quorum)
                        thisThread.interrupt();
                });
            } catch (InterruptedException e) {
                break;
            }
        }

        logger.debug("Exiting state verifier handler thread");
    }

    private boolean isValidState(RecoveryApplicationState state) {
        Commitments recoveryCommitments = state.getTransferPolynomialCommitments();
        if (state.hasState()) {
            ConfidentialSnapshot recoverySnapshot = ConfidentialSnapshot.deserialize(state.getState());
            if (recoverySnapshot == null)
                return false;
            if (recoverySnapshot.getShares() != null) {
                for (ConfidentialData secretData : recoverySnapshot.getShares()) {
                    VerifiableShare share = secretData.getShare();
                    Commitments commitments = commitmentScheme.sumCommitments(share.getCommitments(), recoveryCommitments);
                    if (!commitmentScheme.checkValidity(share.getShare(), commitments))
                        return false;
                }
            }
        }

        CommandsInfo[] recoveryLog = state.getMessageBatches();
        for (CommandsInfo commandsInfo : recoveryLog) {
            for (byte[] command : commandsInfo.commands) {
                Request request = Request.deserialize(command);
                if (request == null)
                    return false;
                if (request.getShares() != null) {
                    for (ConfidentialData secretData : request.getShares()) {
                        VerifiableShare share = secretData.getShare();
                        Commitments commitments = commitmentScheme.sumCommitments(share.getCommitments(), recoveryCommitments);
                        if (!commitmentScheme.checkValidity(share.getShare(), commitments))
                            return false;
                    }
                }
            }
        }
        return true;
    }
}
