package confidential.statemanagement;

import bftsmart.communication.SystemMessage;
import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.MessageContext;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import confidential.ConfidentialData;
import confidential.Utils;
import confidential.server.Request;
import confidential.statemanagement.utils.HashThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Robin
 */
public class RecoveryStateSender extends Thread {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private static final String SECRET = "MySeCreT_2hMOygBwY";
    private int myProcessId;
    private String recoveringServerIp;
    private DefaultApplicationState state;
    private VerifiableShare recoveryPoint;
    private BigInteger field;
    private boolean iAmStateSender;
    private HashThread hashThread;
    private SSLSocketFactory socketFactory;
    private int secureServerPort;
    private int unSecureServerPort;

    RecoveryStateSender(int serverPort, String recoveringServerIp,
                        DefaultApplicationState applicationState, VerifiableShare recoveryPoint,
                        BigInteger field, ServerViewController svController, boolean iAmStateSender) throws Exception {
        super("State Sender Thread");
        this.secureServerPort = serverPort;
        this.unSecureServerPort = serverPort + 1;
        this.recoveringServerIp = recoveringServerIp;
        this.state = applicationState;
        this.recoveryPoint = recoveryPoint;
        this.myProcessId = svController.getStaticConf().getProcessId();
        this.field = field;
        this.iAmStateSender = iAmStateSender;
        this.socketFactory = getSSLSocketFactory(svController);
        this.hashThread = new HashThread();
    }

    private SSLSocketFactory getSSLSocketFactory(ServerViewController svController) throws CertificateException,
            UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        try (FileInputStream fis = new FileInputStream("config/keysSSL_TLS/" +
                svController.getStaticConf().getSSLTLSKeyStore())) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(fis, SECRET.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(ks, SECRET.toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
            trustManagerFactory.init(ks);

            SSLContext context = SSLContext.getInstance(svController.getStaticConf().getSSLTLSProtocolVersion());
            context.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            return context.getSocketFactory();
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException
                | UnrecoverableKeyException | KeyManagementException e) {
            logger.error("Failed to initialize SSL attributes", e);
            throw e;
        }
    }

    @Override
    public void run() {
        logger.debug("Generating recovery state");
        long t1, t2;
        t1 = System.nanoTime();
        BlindedApplicationState recoveryState = createRecoverState();
        t2 = System.nanoTime();
        double total = (t2 - t1) / 1_000_000.0;
        if (recoveryState == null) {
            logger.error("Failed to generate recovery application state. Exiting state sender server thread.");
            return;
        }
        logger.info("Took {} ms to create recovery state of {} shares", total, recoveryState.getShares().size());
        if (!iAmStateSender) {
            hashThread.setData(recoveryState.getCommonState());
            hashThread.start();
            hashThread.update(0, recoveryState.getCommonState().length);
            hashThread.update(-1, -1);
        }
        logger.debug("Transmitting recovery state to {}", recoveringServerIp);
        sendPublicState(recoveryState);
        sendPrivateState(recoveryState.getShares());
        logger.debug("Recovery state sent");

        logger.debug("Exiting state sender server thread");
    }

    private void sendPublicState(BlindedApplicationState state) {
        logger.debug("Connecting un-securely to {}:{}", recoveringServerIp, unSecureServerPort);
        try (Socket unSecureConnection = SocketFactory.getDefault().createSocket(recoveringServerIp, unSecureServerPort);
             BufferedOutputStream out = new BufferedOutputStream(unSecureConnection.getOutputStream())) {
            long t1, t2;
            byte[] commitments = state.getCommitments();
            out.write(Utils.toBytes(myProcessId));
            out.write(Utils.toBytes(commitments.length));
            out.write(commitments);
            logger.info("Commitments has {} bytes", commitments.length);
            out.write(iAmStateSender ? 1 : 0);
            byte[] publicState = state.getCommonState();
            if (iAmStateSender) {
                logger.info("Public state has {} bytes", publicState.length);
                t1 = System.nanoTime();
                out.write(Utils.toBytes(publicState.length));
                out.write(publicState);
            } else {
                byte[] publicStateHash = hashThread.getHash();
                logger.info("Public state hash {}", publicStateHash);
                t1 = System.nanoTime();
                out.write(Utils.toBytes(publicStateHash.length));
                out.write(publicStateHash);
            }
            out.flush();
            t2 = System.nanoTime();
            logger.info("Took {} ms to send public state", (t2 - t1) / 1_000_000.0);
        } catch (IOException e) {
            logger.error("Failed to send public state");
        }
    }

    private void sendPrivateState(LinkedList<Share> privateState) {
        logger.debug("Connecting securely to {}:{}", recoveringServerIp, secureServerPort);
        try (SSLSocket secureConnection = (SSLSocket) socketFactory.createSocket(recoveringServerIp, secureServerPort);
             BufferedOutputStream out = new BufferedOutputStream(secureConnection.getOutputStream())) {
            long t1 = System.nanoTime();
            byte[] serializePrivateState = serializePrivateState(privateState);
            if (serializePrivateState == null) {
                throw new IllegalStateException("Private serialized state is null");
            }
            long t2 = System.nanoTime();
            logger.debug("Took {} ms to serialize private state of {} bytes", (t2 - t1) / 1_000_000.0,
                    serializePrivateState.length);

            t1 = System.nanoTime();
            out.write(Utils.toBytes(myProcessId));
            out.write(Utils.toBytes(serializePrivateState.length));
            out.write(serializePrivateState);
            out.flush();
            t2 = System.nanoTime();
            logger.info("Took {} ms to send private state with {} shares", (t2 - t1) / 1_000_000.0,
                    privateState.size());

        } catch (IOException e) {
            logger.error("Failed to send private state");
        }
    }

    private byte[] serializePrivateState(LinkedList<Share> privateState) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeInt(privateState.size());
            for (Share share : privateState) {
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

    private BlindedApplicationState createRecoverState() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos);
             ByteArrayOutputStream bosCommitments = new ByteArrayOutputStream();
             ObjectOutputStream outCommitments = new ObjectOutputStream(bosCommitments)) {
            CommandsInfo[] log = state.getMessageBatches();
            vss.Utils.writeCommitment(recoveryPoint.getCommitments(), outCommitments);
            out.writeInt(state.getLastCheckpointCID());
            out.writeInt(state.getLastCID());

            out.writeInt(log == null ? -1 : log.length);
            LinkedList<Share> shares = new LinkedList<>();
            byte[] b;
            if (log != null) {
                for (CommandsInfo commandsInfo : log) {
                    byte[][] commands = commandsInfo.commands;
                    MessageContext[] msgCtx = commandsInfo.msgCtx;
                    serializeMessageContext(out, msgCtx);
                    out.writeInt(commands.length);
                    for (byte[] command : commands) {
                        Request request = Request.deserialize(command);
                        if (request == null || request.getShares() == null) {
                            out.writeInt(-1);
                            out.writeInt(command.length);
                            out.write(command);
                        } else {
                            out.writeInt(request.getShares().length);
                            for (ConfidentialData share : request.getShares()) {
                                b = share.getShare().getSharedData();
                                out.writeInt(b == null ? -1 : b.length);
                                if (b != null)
                                    out.write(b);
                                vss.Utils.writeCommitment(share.getShare().getCommitments(), outCommitments);
                                Share transferShare = share.getShare().getShare();
                                transferShare.setShare(transferShare.getShare().add(recoveryPoint.getShare().getShare()).mod(field));
                                shares.add(transferShare);

                                out.writeInt(share.getPublicShares() == null ? -1 : share.getPublicShares().size());
                                if (share.getPublicShares() != null) {//writing public data
                                    for (VerifiableShare publicShare : share.getPublicShares()) {
                                        publicShare.writeExternal(out);
                                    }
                                }
                            }
                            request.setShares(null);
                            b = request.serialize();
                            if (b == null) {
                                logger.debug("Failed to serialize recovery Request");
                                return null;
                            }
                            out.writeInt(b.length);
                            out.write(b);
                        }
                    }
                }
            }

            if (state.hasState()) {
                ConfidentialSnapshot snapshot = ConfidentialSnapshot.deserialize(state.getSerializedState());
                if (snapshot != null) {
                    out.writeBoolean(true);
                    out.writeInt(snapshot.getPlainData() == null ? -1 : snapshot.getPlainData().length);
                    if (snapshot.getPlainData() != null)
                        out.write(snapshot.getPlainData());
                    out.writeInt(snapshot.getShares() == null ? -1 : snapshot.getShares().length);
                    if (snapshot.getShares() != null) {
                        for (ConfidentialData share : snapshot.getShares()) {
                            b = share.getShare().getSharedData();
                            out.writeInt(b == null ? -1 : b.length);
                            if (b != null)
                                out.write(b);
                            vss.Utils.writeCommitment(share.getShare().getCommitments(),
                                    outCommitments);
                            Share transferShare = share.getShare().getShare();
                            transferShare.setShare(transferShare.getShare().add(recoveryPoint.getShare().getShare()).mod(field));
                            shares.add(transferShare);

                            out.writeInt(share.getPublicShares() == null ? -1 : share.getPublicShares().size());
                            if (share.getPublicShares() != null) {//writing public data
                                for (VerifiableShare publicShare : share.getPublicShares()) {
                                    publicShare.writeExternal(out);
                                }
                            }
                        }
                    }
                } else
                    out.writeBoolean(false);
            } else
                out.writeBoolean(false);

            out.flush();
            bos.flush();
            outCommitments.flush();
            bosCommitments.flush();

            byte[] commonState = bos.toByteArray();
            byte[] commitmentsBytes = bosCommitments.toByteArray();

            return new BlindedApplicationState(
                    commonState,
                    shares,
                    commitmentsBytes,
                    state.getLastCheckpointCID(),
                    state.getLastCID(),
                    myProcessId
            );

        } catch (IOException e) {
            logger.error("Failed to create Recovery State", e);
        }
        return null;
    }

    private void serializeMessageContext(ObjectOutputStream out, MessageContext[] msgCtx) throws IOException {
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
