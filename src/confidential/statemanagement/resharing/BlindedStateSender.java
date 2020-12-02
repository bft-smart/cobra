package confidential.statemanagement.resharing;

import bftsmart.communication.SystemMessage;
import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.MessageContext;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import confidential.ConfidentialData;
import confidential.Configuration;
import confidential.server.Request;
import confidential.statemanagement.BlindedApplicationState;
import confidential.statemanagement.ConfidentialSnapshot;
import confidential.statemanagement.HashThread;
import confidential.statemanagement.utils.PublicDataSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

public class BlindedStateSender extends Thread {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private final int processId;
    private final BigInteger field;
    private final int unSecureServerPort;
    private final String[] receiversIp;
    private final DefaultApplicationState state;
    private final VerifiableShare blindingShare;
    private final HashThread commonStateHashThread;
    private final HashThread commitmentHashThread;
    private final boolean iAmStateSender;

    public BlindedStateSender(ServerViewController svController, BigInteger field,
                              int stateReceiverPort, String[] receiversIp,
                              DefaultApplicationState state, VerifiableShare blindingShare, boolean iAmStateSender) throws Exception {
        super("State Sender Thread");
        this.processId = svController.getStaticConf().getProcessId();
        this.field = field;
        this.unSecureServerPort = stateReceiverPort;
        this.receiversIp = receiversIp;
        this.state = state;
        this.blindingShare = blindingShare;
        this.iAmStateSender = iAmStateSender;
        this.commonStateHashThread = new HashThread();
        if (Configuration.getInstance().getVssScheme().equals("1")) {//linear scheme
            this.commitmentHashThread = new HashThread();
        } else {
            this.commitmentHashThread = null;
        }
    }

    @Override
    public void run() {
        logger.debug("Generating blinded state");
        BlindedApplicationState blindedState = createBlindedState(blindingShare, state);
        if (blindedState == null) {
            logger.error("Failed to generate blinded application state. Exiting state sender thread.");
            return;
        }

        if (!iAmStateSender) {
            commonStateHashThread.setData(blindedState.getCommonState());
            commonStateHashThread.start();
            commonStateHashThread.update(0, blindedState.getCommonState().length);
            commonStateHashThread.update(-1, -1);

            if (commitmentHashThread != null) {
                commitmentHashThread.setData(blindedState.getCommitments());
                commitmentHashThread.start();
                commitmentHashThread.update(0, blindedState.getCommitments().length);
                commitmentHashThread.update(-1, -1);
            }
        }
        long t1, t2;
        t1 = System.nanoTime();
        byte[] serializedBlindedShares = serializeBlindedShares(blindedState.getShares());
        t2 = System.nanoTime();
        logger.info("Took {} ms to serialize private state", (t2 - t1) / 1_000_000.0);

        PublicDataSender[] publicDataSenders = new PublicDataSender[receiversIp.length];
        for (int i = 0; i < receiversIp.length; i++) {
            publicDataSenders[i] = new PublicDataSender(receiversIp[i], unSecureServerPort, processId, 3);
            publicDataSenders[i].start();
            publicDataSenders[i].sendData(serializedBlindedShares);
        }

        byte[] commitments = blindedState.getCommitments();
        if (!iAmStateSender && commitmentHashThread != null) {
            commitments = commitmentHashThread.getHash();
        }
        for (PublicDataSender publicDataSender : publicDataSenders) {
            publicDataSender.sendData(commitments);
        }


        byte[] commonState;
        if (iAmStateSender) {
            commonState = blindedState.getCommonState();
        } else {
            commonState = commonStateHashThread.getHash();
        }
        for (PublicDataSender publicDataSender : publicDataSenders) {
            publicDataSender.sendData(commonState);
        }
        logger.debug("Exiting state sender thread");
    }

    private BlindedApplicationState createBlindedState(VerifiableShare blindingShare, DefaultApplicationState state) {
        try (ByteArrayOutputStream bosCommonState = new ByteArrayOutputStream();
             ByteArrayOutputStream bosCommitments = new ByteArrayOutputStream();
             ObjectOutput outCommonState = new ObjectOutputStream(bosCommonState);
             ObjectOutput outCommitments = new ObjectOutputStream(bosCommitments)) {

            LinkedList<Share> blindedShares= new LinkedList<>();

            CommandsInfo[] log = state.getMessageBatches();

            vss.Utils.writeCommitment(blindingShare.getCommitments(), outCommitments);

            outCommonState.writeInt(state.getLastCheckpointCID());
            outCommonState.writeInt(state.getLastCID());

            outCommonState.writeInt(log == null ? -1 : log.length);

            if (log != null) {
                serializeLog(log, blindingShare, outCommonState, outCommitments, blindedShares);
            }

            ConfidentialSnapshot snapshot = null;
            if (state.hasState())
                snapshot = ConfidentialSnapshot.deserialize(state.getSerializedState());

            if (snapshot != null) {
                outCommonState.writeBoolean(true);
                serializeSnapshot(snapshot, blindingShare, outCommonState, outCommitments, blindedShares);
            } else
                outCommonState.writeBoolean(false);

            bosCommonState.flush();
            bosCommitments.flush();
            outCommonState.flush();
            outCommitments.flush();

            byte[] commonStateBytes = bosCommonState.toByteArray();
            byte[] commitmentsBytes = bosCommitments.toByteArray();
            return new BlindedApplicationState(
                    commonStateBytes,
                    blindedShares,
                    commitmentsBytes,
                    state.getLastCheckpointCID(),
                    state.getLastCID(),
                    processId
            );
        } catch (IOException e) {
            logger.error("Failed to create Blinded State", e);
            return null;
        }
    }

    private void serializeSnapshot(ConfidentialSnapshot snapshot, VerifiableShare blindingShare,
                                   ObjectOutput outCommonState, ObjectOutput outCommitments, LinkedList<Share> blindedShares) throws IOException {
        byte[] b;
        Share blindedShare;
        outCommonState.writeInt(snapshot.getPlainData() == null ? -1 : snapshot.getPlainData().length);
        if (snapshot.getPlainData() != null)
            outCommonState.write(snapshot.getPlainData());
        outCommonState.writeInt(snapshot.getShares() == null ? -1 : snapshot.getShares().length);
        if (snapshot.getShares() != null) {
            for (ConfidentialData share : snapshot.getShares()) {
                b = share.getShare().getSharedData();
                outCommonState.writeInt(b == null ? -1 : b.length);
                if (b != null)
                    outCommonState.write(b);
                vss.Utils.writeCommitment(share.getShare().getCommitments(), outCommitments);
                blindedShare = share.getShare().getShare();
                blindedShare.setShare(blindedShare.getShare().add(blindingShare.getShare().getShare()).mod(field));
                blindedShares.add(blindedShare);
            }
        }
    }

    private void serializeLog(CommandsInfo[] log, VerifiableShare blindingShare, ObjectOutput outCommonState,
                              ObjectOutput outCommitments, LinkedList<Share> blindedShares) throws IOException {
        byte[] b;
        Share blindedShare;
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
                    for (ConfidentialData share : request.getShares()) {
                        b = share.getShare().getSharedData();
                        outCommonState.writeInt(b == null ? -1 : b.length);
                        if (b != null)
                            outCommonState.write(b);
                        vss.Utils.writeCommitment(share.getShare().getCommitments(), outCommitments);
                        blindedShare = share.getShare().getShare();
                        blindedShare.setShare(blindedShare.getShare().add(blindingShare.getShare().getShare()).mod(field));
                        blindedShares.add(blindedShare);
                    }
                    request.setShares(null);
                    b = request.serialize();
                    if (b == null) {
                        logger.debug("Failed to serialize blinded Request");
                        return;
                    }
                    outCommonState.writeInt(b.length);
                    outCommonState.write(b);
                }
            }
        }
    }

    private byte[] serializeBlindedShares(LinkedList<Share> blindedShares) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeInt(blindedShares.size());
            for (Share share : blindedShares) {
                share.writeExternal(out);
            }
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Failed to serialize Shares");
            return null;
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
            ctx.getFirstInBatch().wExternal(out);
            out.writeBoolean(ctx.isLastInBatch());
            out.writeBoolean(ctx.isNoOp());
            //out.writeBoolean(ctx.readOnly);

            out.writeInt(ctx.getNonces() == null ? -1 : ctx.getNonces().length);
            if (ctx.getNonces() != null)
                out.write(ctx.getNonces());
        }

    }
}
