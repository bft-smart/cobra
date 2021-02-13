package confidential.statemanagement.privatestate.receiver;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.MessageContext;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import confidential.ConfidentialData;
import confidential.Configuration;
import confidential.server.Request;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.ConfidentialSnapshot;
import confidential.statemanagement.ReconstructionCompleted;
import confidential.statemanagement.privatestate.commitments.BlindedCommitmentHandler;
import confidential.statemanagement.privatestate.commitments.ConstantCommitmentHandler;
import confidential.statemanagement.privatestate.commitments.LinearCommitmentHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.interpolation.InterpolationStrategy;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public abstract class BlindedStateHandler extends Thread {
    protected final Logger logger = LoggerFactory.getLogger("state_transfer");
    private final int pid;
    protected final BigInteger shareholderId;
    protected final BigInteger field;
    protected final AtomicInteger corruptedServers;
    protected final int f;
    private final int quorum;
    private final int stateSenderReplica;
    protected final ServerConfidentialityScheme confidentialityScheme;
    protected final CommitmentScheme commitmentScheme;
    protected final InterpolationStrategy interpolationStrategy;
    private final ReconstructionCompleted reconstructionListener;
    private final BlindedCommitmentHandler commitmentsHandler;

    private final Lock lock;
    private final Condition waitingBlindedDataCondition;

    protected final Set<Integer> stillValidSenders;

    private final Map<Integer, Integer> commonState;
    private byte[] selectedCommonState;
    private int selectedCommonStateHash;
    private ObjectInput commonStateStream;
    private int nCommonStateReceived;

    private final Map<Integer, Share[]> allBlindedShares;
    private final Map<Integer, Integer> blindedSharesSize;
    private int correctBlindedSharesSize;

    public BlindedStateHandler(ServerViewController svController, int serverPort, int f, int quorum,
                               int stateSenderReplica, ServerConfidentialityScheme confidentialityScheme,
                               ReconstructionCompleted reconstructionListener) {
        this.pid = svController.getStaticConf().getProcessId();
        this.shareholderId = confidentialityScheme.getMyShareholderId();
        this.field = confidentialityScheme.getField();
        this.corruptedServers = new AtomicInteger(0);
        this.f = f;
        this.quorum = quorum;
        this.stateSenderReplica = stateSenderReplica;
        this.confidentialityScheme = confidentialityScheme;
        this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
        this.interpolationStrategy = confidentialityScheme.getInterpolationStrategy();
        this.reconstructionListener = reconstructionListener;
        this.lock = new ReentrantLock(true);
        this.waitingBlindedDataCondition = lock.newCondition();

        this.stillValidSenders = ConcurrentHashMap.newKeySet(quorum);
        this.commonState = new HashMap<>(quorum);
        this.allBlindedShares = new HashMap<>(quorum);
        this.blindedSharesSize = new HashMap<>(quorum);
        this.correctBlindedSharesSize = -1;

        if (Configuration.getInstance().getVssScheme().equals("1")) {//linear scheme
            this.commitmentsHandler = new LinearCommitmentHandler(f, quorum, stateSenderReplica);
        } else {
            this.commitmentsHandler = new ConstantCommitmentHandler(quorum, confidentialityScheme);
        }

        int port = serverPort + pid;
        try {
            BlindedDataReceiver blindedDataReceiver = new BlindedDataReceiver(this, svController,
                    port, quorum, stateSenderReplica);
            blindedDataReceiver.start();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to initialize blinded data receiver thread", e);
        }
    }

    public void deliverBlindedData(int from, byte[][] shares, byte[] serializedCommonState, byte[] commonStateHash,
                                            Commitment[] commitments, byte[] commitmentsHash) {
        lock.lock();

        if (commonStateStream == null) {
            int commonStateHashCode = Arrays.hashCode(commonStateHash);
            if (from == stateSenderReplica) {
                selectedCommonState = serializedCommonState;
                selectedCommonStateHash = commonStateHashCode;
                logger.debug("Replica {} sent me a common state of {} bytes", from, serializedCommonState.length);
            } else {
                logger.debug("Replica {} sent me common state hash", from);
            }

            commonState.merge(commonStateHashCode, 1, Integer::sum);

            commitmentsHandler.handleNewCommitments(from, commitments, commitmentsHash);

            nCommonStateReceived++;
        }

        Share[] blindedShares = reconstructBlindedShares(from, shares);
        if (blindedShares == null) {
            logger.warn("Failed to reconstruct blinded shares from {}", from);
        } else {
            this.allBlindedShares.put(from, blindedShares);
            this.blindedSharesSize.merge(blindedShares.length, 1, Integer::sum);
            stillValidSenders.add(from);
        }

        waitingBlindedDataCondition.signal();
        lock.unlock();
    }

    protected abstract Share[] reconstructBlindedShares(int from, byte[][] shares);

    protected abstract Iterator<VerifiableShare> reconstructShares(int nShares,
                                                                   Map<Integer, Share[]> allBlindedShares,
                                                                   Map<BigInteger, Commitment[]> allBlindedCommitments);

    @Override
    public void run() {
        while (true) {
            try {
                lock.lock();
                waitingBlindedDataCondition.await();
                if (allBlindedShares.size() < quorum || selectedCommonState == null || nCommonStateReceived < quorum) {
                    continue;
                }
                if (commonStateStream == null) {
                    if (haveCorrectState(selectedCommonState, commonState, selectedCommonStateHash)) {
                        commonStateStream = new ObjectInputStream(new ByteArrayInputStream(selectedCommonState));
                    } else {
                        logger.debug("I don't have enough same common states");
                    }
                }

                if (!commitmentsHandler.prepareCommitments()) {
                    continue;
                }

                if (correctBlindedSharesSize == -1) {
                    correctBlindedSharesSize = selectCorrectKey(blindedSharesSize);
                }

                if (commonStateStream != null && correctBlindedSharesSize != -1) {
                    logger.info("Reconstructing state");
                    long startTime = System.nanoTime();
                    DefaultApplicationState reconstructedState = reconstructState();
                    if (reconstructedState == null) {
                        logger.error("Reconstructed state is null. Waiting for more blinded shares.");
                        continue;
                    }
                    long endTime = System.nanoTime();
                    double totalTime = (endTime - startTime) / 1_000_000.0;
                    logger.info("Took {} ms to reconstruct state", totalTime);
                    reconstructionListener.onReconstructionCompleted(reconstructedState);
                    break;
                }

            } catch (InterruptedException | IOException | ClassNotFoundException e) {
                logger.error("Failed to reconstruct state", e);
                break;
            } finally {
                lock.unlock();
            }
        }

        logger.debug("Exiting blinded state handler thread");
    }

    private DefaultApplicationState reconstructState() throws IOException, ClassNotFoundException {

        //Collecting all commitments
        Set<BigInteger> validShareholders = new HashSet<>(stillValidSenders.size());
        for (Integer validSender : stillValidSenders) {
            validShareholders.add(confidentialityScheme.getShareholder(validSender));
        }

        Map<BigInteger, Commitment[]> allBlindedCommitments = commitmentsHandler.readAllCommitments(validShareholders);

        long t1, t2;
        t1 = System.nanoTime();
        Iterator<VerifiableShare> reconstructedShares = reconstructShares(correctBlindedSharesSize, allBlindedShares,
                allBlindedCommitments);
        t2 = System.nanoTime();
        if (reconstructedShares == null) {
            logger.error("Failed to reconstruct shares");
            return null;
        }
        double duration = (t2 - t1) / 1_000_000.0;
        logger.info("Took {} ms to reconstruct {} shares", duration, correctBlindedSharesSize);

        int lastCheckPointCID = commonStateStream.readInt();
        int lastCID = commonStateStream.readInt();
        int logSize = commonStateStream.readInt();

        CommandsInfo[] reconstructedLog = null;
        if (logSize != -1)  {
            reconstructedLog = reconstructLog(logSize, reconstructedShares);
            if (reconstructedLog == null) {
                logger.error("Failed to reconstruct log");
                return null;
            }
        }

        boolean hasState = commonStateStream.readBoolean();
        ConfidentialSnapshot reconstructedSnapshot = null;
        if (hasState) {
            reconstructedSnapshot = reconstructSnapshot(reconstructedShares);
        }

        byte[] reconstructedSerializedState = reconstructedSnapshot == null ? null : reconstructedSnapshot.serialize();

        return new DefaultApplicationState(
                reconstructedLog,
                lastCheckPointCID,
                lastCID,
                reconstructedSerializedState,
                reconstructedSerializedState == null ? null : TOMUtil.computeHash(reconstructedSerializedState),
                pid
        );
    }

    private ConfidentialSnapshot reconstructSnapshot(Iterator<VerifiableShare> reconstructedShares) throws IOException {
        logger.info("Reconstructing snapshot");
        int plainDataSize = commonStateStream.readInt();
        byte[] plainData = null;
        if (plainDataSize > -1) {
            plainData = new byte[plainDataSize];
            commonStateStream.readFully(plainData);
        }

        int nShares = commonStateStream.readInt();
        ConfidentialData[] snapshotShares = null;
        if (nShares > -1) {
            snapshotShares = getRefreshedShares(nShares, reconstructedShares);
        }

        return snapshotShares == null ?
                new ConfidentialSnapshot(plainData)
                : new ConfidentialSnapshot(plainData, snapshotShares);
    }

    private CommandsInfo[] reconstructLog(int logSize, Iterator<VerifiableShare> reconstructedShares) throws IOException {
        logger.info("Reconstructing log");
        CommandsInfo[] log = new CommandsInfo[logSize];
        for (int i = 0; i < logSize; i++) {
            MessageContext[] msgCtx = deserializeMessageContext(commonStateStream);
            int nCommands = commonStateStream.readInt();
            byte[][] commands = new byte[nCommands][];
            for (int j = 0; j < nCommands; j++) {
                int nShares = commonStateStream.readInt();
                byte[] command;
                if (nShares == -1) {
                    command = new byte[commonStateStream.readInt()];
                    commonStateStream.readFully(command);
                } else {
                    ConfidentialData[] shares = getRefreshedShares(nShares, reconstructedShares);

                    byte[] b = new byte[commonStateStream.readInt()];
                    commonStateStream.readFully(b);
                    Request request = Request.deserialize(b);
                    if (request == null) {
                        logger.error("Failed to deserialize request");
                        return null;
                    }
                    request.setShares(shares);
                    command = request.serialize();
                    if (command == null) {
                        logger.error("Failed to serialize request");
                        return null;
                    }
                }
                commands[j] = command;
            }
            log[i] = new CommandsInfo(commands, msgCtx);
        }
        return log;
    }

    private ConfidentialData[] getRefreshedShares(int nShares, Iterator<VerifiableShare> reconstructedShares)
            throws IOException {
        ConfidentialData[] shares = new ConfidentialData[nShares];
        for (int i = 0; i < nShares; i++) {
            int shareDataSize = commonStateStream.readInt();
            byte[] sharedData = null;
            if (shareDataSize > -1) {
                sharedData = new byte[shareDataSize];
                commonStateStream.readFully(sharedData);
            }
            VerifiableShare vs = reconstructedShares.next();
            reconstructedShares.remove();
            vs.setSharedData(sharedData);
            shares[i] = new ConfidentialData(vs);
        }
        return shares;
    }

    private boolean haveCorrectState(byte[] selectedState, Map<Integer, Integer> states,
                                       int selectedStateHash) {
        if (selectedState == null)
            return false;
        Optional<Map.Entry<Integer, Integer>> max = states.entrySet().stream()
                .max(Comparator.comparingInt(Map.Entry::getValue));
        if (!max.isPresent()) {
            logger.info("I don't have correct common state");
            return false;
        }
        Map.Entry<Integer, Integer> entry = max.get();
        if (entry.getValue() <= f) {
            logger.info("I don't have correct common state");
            return false;
        }

        return selectedStateHash == entry.getKey();
    }

    private int selectCorrectKey(Map<Integer, Integer> keys) {
        int max = 0;
        int key = -1;
        for (Map.Entry<Integer, Integer> entry : keys.entrySet()) {
            if (entry.getValue() > max) {
                max = entry.getValue();
                key = entry.getKey();
            }
        }

        if (max <= f)
            return -1;
        return key;
    }

    private MessageContext[] deserializeMessageContext(ObjectInput in) throws IOException {
        int size = in.readInt();
        if (size == -1)
            return null;
        MessageContext[] messageContexts = new MessageContext[size];
        for (int i = 0; i < size; i++) {
            int sender = in.readInt();
            int viewId = in.readInt();
            TOMMessageType type = TOMMessageType.fromInt(in.readInt());
            int session = in.readInt();
            int sequence = in.readInt();
            int operationId = in.readInt();
            int replyServer = in.readInt();
            int len = in.readInt();
            byte[] signature = null;
            if (len != -1) {
                signature = new byte[len];
                in.readFully(signature);
            }
            long timestamp = in.readLong();
            int regency = in.readInt();
            int leader = in.readInt();
            int consensusId = in.readInt();
            int numOfNonces = in.readInt();
            long seed = in.readLong();
            len = in.readInt();
            byte[] metadata = null;
            if (len > -1) {
                metadata = new byte[len];
                in.readFully(metadata);
            }
            len = in.readInt();
            Set<ConsensusMessage> proof = null;
            if (len != -1) {
                proof = new HashSet<>(len);
                while (len-- > 0) {
                    int from = -1;//in.readInt();
                    int number = in.readInt();
                    int epoch = in.readInt();
                    int paxosType = in.readInt();
                    int valueSize = in.readInt();
                    byte[] value = null;
                    if (valueSize != -1) {
                        value = new byte[valueSize];
                        in.readFully(value);
                    }

                    ConsensusMessage p = new ConsensusMessage(paxosType, number, epoch, from, value);
                    proof.add(p);
                }
            }

            TOMMessage firstInBatch = new TOMMessage();
            //firstInBatch.rExternal(in);
            boolean lastInBatch = in.readBoolean();
            boolean noOp = in.readBoolean();
            //boolean readOnly = in.readBoolean();

            len = in.readInt();
            byte[] nonce;
            if (len != -1) {
                nonce = new byte[len];
                in.readFully(nonce);
            }

            MessageContext messageContext = new MessageContext(sender, viewId, type, session, sequence, operationId,
                    replyServer, signature, timestamp, numOfNonces, seed, regency, leader, consensusId,
                    proof, firstInBatch, noOp, metadata);
            if (lastInBatch)
                messageContext.setLastInBatch();
            messageContexts[i] = messageContext;
        }

        return messageContexts;
    }
}
