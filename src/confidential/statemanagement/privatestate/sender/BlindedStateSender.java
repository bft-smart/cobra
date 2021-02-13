package confidential.statemanagement.privatestate.sender;

import bftsmart.communication.SystemMessage;
import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.MessageContext;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import confidential.ConfidentialData;
import confidential.server.Request;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.ConfidentialSnapshot;
import confidential.statemanagement.utils.HashThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public abstract class BlindedStateSender extends Thread {
    protected final Logger logger = LoggerFactory.getLogger("state_transfer");
    private final ServerViewController svController;
    private final int stateLastCID;
    private final int pid;
    private DefaultApplicationState applicationState;
    private final int blindedStateReceiverPort;
    protected final ServerConfidentialityScheme confidentialityScheme;
    private final boolean iAmStateSender;
    private VerifiableShare[] blindingShares;
    private final StateSeparationListener stateSeparationListener;
    protected final int[] blindedStateReceivers;
    private final Lock lock;
    private final Condition waitingBlindingSharesCondition;

    public BlindedStateSender(ServerViewController svController, DefaultApplicationState applicationState,
                              int blindedStateReceiverPort, ServerConfidentialityScheme confidentialityScheme,
                              boolean iAmStateSender, StateSeparationListener stateSeparationListener,
                              int... blindedStateReceivers) {
        super("Blinded State Sender Thread");
        this.svController = svController;
        this.pid = svController.getStaticConf().getProcessId();
        this.applicationState = applicationState;
        this.stateLastCID = applicationState.getLastCID();
        this.blindedStateReceiverPort = blindedStateReceiverPort;
        this.confidentialityScheme = confidentialityScheme;
        this.iAmStateSender = iAmStateSender;
        this.stateSeparationListener = stateSeparationListener;
        this.blindedStateReceivers = blindedStateReceivers;
        this.lock = new ReentrantLock(true);
        this.waitingBlindingSharesCondition = lock.newCondition();
    }

    public int getStateLastCID() {
        return stateLastCID;
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
        BlindedDataSender[] stateSenders;
        try {
            long t1, t2, totalElapsed = 0;
            t1 = System.nanoTime();
            SeparatedState separatedState = separatePrivateState(applicationState);
            t2 = System.nanoTime();
            totalElapsed += t2 - t1;
            applicationState = null;

            if (separatedState == null) {
                logger.error("Separated state is null. Exiting blinded state sender thread.");
                return;
            }
            stateSeparationListener.onSeparation(separatedState.getShares().size());
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
                    stateSender.setCommonState(separatedState.getCommonState(), null);
                }
            } else {
                commonStateHashThread = new HashThread();
                commonStateHashThread.setData(separatedState.getCommonState());
                commonStateHashThread.start();
                commonStateHashThread.update(0, separatedState.getCommonState().length);
                commonStateHashThread.update(-1, -1);
            }
            lock.lock();
            try {
                if (blindingShares == null)
                    waitingBlindingSharesCondition.await();
            } catch (InterruptedException e) {
                logger.error("Failed to wait for blinding shares. Exiting blinded state sender thread.", e);
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
            BlindedShares blindedShares = computeBlindedShares(separatedState.getShares(),
                    separatedState.getCommitments(), blindingShares);
            t2 = System.nanoTime();
            blindingShares = null;
            totalElapsed += t2 - t1;
            double total = totalElapsed / 1_000_000.0;
            if (blindedShares == null) {
                logger.error("Blinded shares are null. Exiting blinded state sender thread.");
                return;
            }
            logger.info("Took {} ms to compute blinded state", total);

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

    private SeparatedState separatePrivateState(DefaultApplicationState state) {
        try (ByteArrayOutputStream bosCommonState = new ByteArrayOutputStream();
             ObjectOutput outCommonState = new ObjectOutputStream(bosCommonState)) {
            LinkedList<Share> sharesToSend = new LinkedList<>();
            LinkedList<Commitment> commitmentsToSend = new LinkedList<>();

            CommandsInfo[] log = state.getMessageBatches();
            outCommonState.writeInt(state.getLastCheckpointCID());
            outCommonState.writeInt(state.getLastCID());

            outCommonState.writeInt(log == null ? -1 : log.length);

            if (log != null) {
                separateLog(log, outCommonState, sharesToSend, commitmentsToSend);
            }

            ConfidentialSnapshot snapshot = null;
            if (state.hasState()) {
                snapshot = ConfidentialSnapshot.deserialize(state.getSerializedState());
            }

            if (snapshot != null) {
                outCommonState.writeBoolean(true);
                separateSnapshot(snapshot, outCommonState, sharesToSend, commitmentsToSend);
            } else {
                outCommonState.writeBoolean(false);
            }

            outCommonState.flush();
            bosCommonState.flush();

            byte[] commonStateBytes = bosCommonState.toByteArray();
            return new SeparatedState(
                    commonStateBytes,
                    sharesToSend,
                    commitmentsToSend
            );
        } catch (IOException e) {
            logger.error("Failed to create separate private state", e);
            return null;
        }
    }

    private void separateSnapshot(ConfidentialSnapshot snapshot, ObjectOutput outCommonState,
                                  LinkedList<Share> sharesToSend, LinkedList<Commitment> commitmentsToSend) throws IOException {
        outCommonState.writeInt(snapshot.getPlainData() == null ? -1 : snapshot.getPlainData().length);
        if (snapshot.getPlainData() != null) {
            outCommonState.write(snapshot.getPlainData());
        }
        outCommonState.writeInt(snapshot.getShares() == null ? -1 : snapshot.getShares().length);
        if (snapshot.getShares() != null) {
            separateShares(snapshot.getShares(), outCommonState, sharesToSend, commitmentsToSend);
        }
    }

    private void separateLog(CommandsInfo[] log, ObjectOutput outCommonState, LinkedList<Share> sharesToSend,
                             LinkedList<Commitment> commitmentsToSend) throws IOException {
        byte[] b;
        for (CommandsInfo commandsInfo : log) {
            byte[][] commands = commandsInfo.commands;
            MessageContext[] msgCtx = commandsInfo.msgCtx;
            serializeMessageContext(outCommonState, msgCtx);
            outCommonState.writeInt(commands.length);
            for (byte[] command : commands) {
                Request request = Request.deserialize(command);
                if (request == null || request.getShares() == null) {
                    outCommonState.writeInt(-1);
                    outCommonState.writeInt(command.length);
                    outCommonState.write(command);
                } else {
                    outCommonState.writeInt(request.getShares().length);
                    separateShares(request.getShares(), outCommonState, sharesToSend, commitmentsToSend);
                    request.setShares(null);
                    b = request.serialize();
                    if (b == null) {
                        logger.debug("Failed to serialize blinded request");
                        return;
                    }
                    outCommonState.writeInt(b.length);
                    outCommonState.write(b);
                }
            }
        }
    }

    private void separateShares(ConfidentialData[] shares, ObjectOutput outCommonState,
                                LinkedList<Share> sharesToSend, LinkedList<Commitment> commitmentsToSend) throws IOException {
        byte[] b;
        for (ConfidentialData share : shares) {
            b = share.getShare().getSharedData();
            outCommonState.writeInt(b == null ? -1 : b.length);
            if (b != null) {
                outCommonState.write(b);
            }
            sharesToSend.add(share.getShare().getShare());
            commitmentsToSend.add(share.getShare().getCommitments());
        }
    }

    private void serializeMessageContext(ObjectOutput out, MessageContext[] msgCtx) throws IOException {
        out.writeInt(msgCtx == null ? -1 : msgCtx.length);
        if (msgCtx == null)
            return;
        for (MessageContext ctx : msgCtx) {
            out.writeInt(ctx.getSender());
            out.writeInt(ctx.getViewID());
            out.writeInt(ctx.getType().ordinal());
            out.writeInt(ctx.getSession());
            out.writeInt(ctx.getSequence());
            out.writeInt(ctx.getOperationId());
            out.writeInt(ctx.getReplyServer());
            out.writeInt(ctx.getSignature() == null ? -1 : ctx.getSignature().length);
            if (ctx.getSignature() != null)
                out.write(ctx.getSignature());

            out.writeLong(ctx.getTimestamp());
            out.writeInt(ctx.getRegency());
            out.writeInt(ctx.getLeader());
            out.writeInt(ctx.getConsensusId());
            out.writeInt(ctx.getNumOfNonces());
            out.writeLong(ctx.getSeed());
            out.writeInt(ctx.getMetadata() == null ? -1 : ctx.getMetadata().length);
            if (ctx.getMetadata() != null) {
                out.write(ctx.getMetadata());
            }
            out.writeInt(ctx.getProof() == null ? -1 : ctx.getProof().size());
            if (ctx.getProof() != null) {
                List<ConsensusMessage> orderedProf = new ArrayList<>(ctx.getProof());
                orderedProf.sort(Comparator.comparingInt(SystemMessage::getSender));
                for (ConsensusMessage proof : orderedProf) {
                    //logger.info("{} {} {} {} {}", proof.getSender(), proof.getNumber(),
                    //        proof.getEpoch(), proof.getType(), proof.getValue());
                    //out.writeInt(proof.getSender());
                    out.writeInt(proof.getNumber());
                    out.writeInt(proof.getEpoch());
                    out.writeInt(proof.getType());

                    out.writeInt(proof.getValue() == null ? -1 : proof.getValue().length);
                    if (proof.getValue() != null)
                        out.write(proof.getValue());
                    /*logger.debug("{}", proof.getProof());*/
                }
            }
            //ctx.getFirstInBatch().wExternal(out);
            out.writeBoolean(ctx.isLastInBatch());
            out.writeBoolean(ctx.isNoOp());
            //out.writeBoolean(ctx.readOnly);

            out.writeInt(ctx.getNonces() == null ? -1 : ctx.getNonces().length);
            if (ctx.getNonces() != null)
                out.write(ctx.getNonces());
        }

    }
}
