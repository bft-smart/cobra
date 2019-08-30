package confidential.statemanagement;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.tom.MessageContext;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import confidential.ConfidentialData;
import confidential.server.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.CommitmentScheme;
import vss.commitment.Commitments;
import vss.facade.SecretSharingException;
import vss.interpolation.InterpolationStrategy;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class StateRecoveryHandler extends Thread {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private final int threshold;
    private final BigInteger field;
    private BlockingQueue<RecoverySMMessage> stateQueue;
    private int corruptedServers;

    private CommitmentScheme commitmentScheme;
    private InterpolationStrategy interpolationStrategy;

    private Map<Integer, Commitments> polynomialCommitments;
    private Map<Integer, Integer> polynomialCommitmentsSenders;
    private Commitments transferPolynomialCommitments;

    private Map<Integer, byte[]> commonData;
    private Map<Integer, Integer> commonDataSender;

    private Map<Integer, LinkedList<Share>> recoveryShares;
    private Map<Integer, Integer> recoverySharesSize;
    private int correctRecoverySharesSize;

    private Map<Integer, Integer> lastCheckpointCIDSenders;
    private Map<Integer, Integer> lastCIDSenders;

    private int pid;
    private BigInteger shareholderId;

    private ObjectInputStream commonDataStream;
    private ReconstructionCompleted reconstructionListener;

    public StateRecoveryHandler(ReconstructionCompleted reconstructionListener, int threshold, int pid,
                                BigInteger field, CommitmentScheme commitmentScheme,
                                InterpolationStrategy interpolationStrategy) {
        super("State Recovery Handler Thread");
        this.reconstructionListener = reconstructionListener;
        this.threshold = threshold;
        this.pid = pid;
        this.shareholderId = BigInteger.valueOf(pid + 1);
        this.field = field;

        this.commitmentScheme = commitmentScheme;
        this.interpolationStrategy = interpolationStrategy;

        this.stateQueue = new LinkedBlockingQueue<>();

        this.commonData = new HashMap<>(threshold + 1);
        this.commonDataSender = new HashMap<>(threshold + 1);

        this.recoveryShares = new HashMap<>(threshold + 1);
        this.recoverySharesSize = new HashMap<>(threshold + 1);
        this.correctRecoverySharesSize = -1;

        this.polynomialCommitments = new HashMap<>(threshold + 1);
        this.polynomialCommitmentsSenders = new HashMap<>(threshold + 1);
        this.lastCheckpointCIDSenders = new HashMap<>(threshold + 1);
        this.lastCIDSenders = new HashMap<>(threshold + 1);
    }

    public void deliverRecoveryState(RecoverySMMessage state) {
        try {
            stateQueue.put(state);
        } catch (InterruptedException e) {
            logger.error("Failed to add recovery state", e);
        }
    }

    @Override
    public void run() {
        while (true) {
            try {
                RecoverySMMessage recoveryMessage = stateQueue.take();
                RecoveryApplicationState state = recoveryMessage.getRecoveryState();

                //to select correct recovery polynomial commitments
                if (transferPolynomialCommitments == null) {
                    int transferPolynomialCommitmentsHashCode = state.getTransferPolynomialCommitments().hashCode();
                    polynomialCommitments.computeIfAbsent(transferPolynomialCommitmentsHashCode,
                            k -> state.getTransferPolynomialCommitments());
                    polynomialCommitmentsSenders.merge(transferPolynomialCommitmentsHashCode,
                            1, Integer::sum);
                }

                //to select correct common state
                if (commonDataStream == null) {
                    int commonDataHashCode = Arrays.hashCode(state.getCommonState());
                    commonData.computeIfAbsent(commonDataHashCode, k -> state.getCommonState());
                    commonDataSender.merge(commonDataHashCode, 1, Integer::sum);
                }

                //to select correct recovery shares
                recoveryShares.put(recoveryMessage.getSender(), state.getShares());
                recoverySharesSize.merge(state.getShares().size(), 1, Integer::sum);

                lastCheckpointCIDSenders.merge(state.getLastCheckpointCID(), 1, Integer::sum);
                lastCIDSenders.merge(state.getLastCID(), 1, Integer::sum);

                if (recoveryShares.size() < 2 * threshold + 1)
                    continue;

                logger.debug("RecoveryStates: {}", recoveryShares.size());

                if (transferPolynomialCommitments == null)
                    transferPolynomialCommitments = selectCorrectData(polynomialCommitmentsSenders,
                            polynomialCommitments);

                if (commonDataStream == null) {
                    byte[] correctCommonData = selectCorrectData(commonDataSender, commonData);
                    if (correctCommonData != null)
                        commonDataStream = new ObjectInputStream(new ByteArrayInputStream(correctCommonData));
                }
                if (correctRecoverySharesSize == -1)
                    correctRecoverySharesSize = selectCorrectKey(recoverySharesSize);

                if (commonDataStream != null && correctRecoverySharesSize != -1) {
                    long startTime = System.nanoTime();
                    DefaultApplicationState recoveredState = recoverState();
                    long endTime = System.nanoTime();
                    double totalTime = (endTime - startTime) / 1_000_000.0;
                    logger.info("State Reconstruction duration: {} ms", totalTime);
                    reconstructionListener.onReconstructionCompleted(recoveredState);
                    break;
                }
            } catch (InterruptedException e) {
                logger.error("Failed to poll state from queue", e);
            } catch (IOException e) {
                logger.debug("Failed to load common data");
            }
        }

        logger.debug("Exiting state recovery handler thread");
    }

    private MessageContext[] deserializeMessageContext(ObjectInputStream in) throws IOException, ClassNotFoundException {
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
            firstInBatch.rExternal(in);
            boolean lastInBatch = in.readBoolean();
            boolean noOp = in.readBoolean();
            //boolean readOnly = in.readBoolean();

            len = in.readInt();
            byte[] nonces = null;
            if (len != -1) {
                nonces = new byte[len];
                in.readFully(nonces);
            }

            MessageContext messageContext = new MessageContext(sender, viewId, type, session, sequence, operationId,
                    replyServer, signature, timestamp, numOfNonces, seed, regency, leader, consensusId,
                    proof, firstInBatch, noOp);
            if (lastInBatch)
                messageContext.setLastInBatch();
            messageContexts[i] = messageContext;
        }

        return messageContexts;
    }

    private DefaultApplicationState recoverState() {
        try {
            Map<Integer, Iterator<Share>> currentShares = new HashMap<>(recoveryShares.size());
            for (Map.Entry<Integer, LinkedList<Share>> entry : recoveryShares.entrySet()) {
                currentShares.put(entry.getKey(), entry.getValue().iterator());
            }

            int logSize = commonDataStream.readInt();
            CommandsInfo[] log = null;
            if (logSize != -1) {
                log = new CommandsInfo[logSize];
                for (int i = 0; i < logSize; i++) {
                    MessageContext[] msgCtx = deserializeMessageContext(commonDataStream);
                    int nCommands = commonDataStream.readInt();
                    byte[][] commands = new byte[nCommands][];
                    for (int j = 0; j < nCommands; j++) {
                        int nShares = commonDataStream.readInt();
                        byte[] command;
                        if (nShares == -1) {
                            command = new byte[commonDataStream.readInt()];
                            commonDataStream.readFully(command);
                        } else {
                            ConfidentialData[] shares = new ConfidentialData[nShares];

                            for (int s = 0; s < nShares; s++) {
                                int shareDataSize = commonDataStream.readInt();
                                byte[] sharedData = null;
                                if (shareDataSize != -1) {
                                    sharedData = new byte[shareDataSize];
                                    commonDataStream.readFully(sharedData);
                                }
                                Commitments commitments = new Commitments();
                                commitments.readExternal(commonDataStream);

                                Share share = recoverShare(currentShares, commitments);

                                if (share == null) {
                                    return null;
                                }

                                VerifiableShare vs = new VerifiableShare(share, commitments, sharedData);
                                int nPublicShares = commonDataStream.readInt();
                                LinkedList<VerifiableShare> publicShares = null;

                                if (nPublicShares != -1) {
                                    publicShares = new LinkedList<>();
                                    while (nPublicShares-- > 0) {
                                        VerifiableShare v = new VerifiableShare();
                                        v.readExternal(commonDataStream);
                                        publicShares.add(v);
                                    }
                                }

                                shares[s] = publicShares == null ?
                                        new ConfidentialData(vs) : new ConfidentialData(vs, publicShares);
                            }

                            byte[] b = new byte[commonDataStream.readInt()];
                            commonDataStream.readFully(b);
                            Request request = Request.deserialize(b);
                            if (request == null) {
                                logger.error("Failed to deserialize recovery request");
                                return null;
                            }
                            request.setShares(shares);
                            command = request.serialize();
                        }

                        commands[j] = command;
                    }
                    log[i] = new CommandsInfo(commands, msgCtx);
                }
            }

            boolean hasState = commonDataStream.readBoolean();
            ConfidentialSnapshot snapshot = null;
            if (hasState) {
                int plainDataSize = commonDataStream.readInt();
                byte[] plainData = null;
                if (plainDataSize != -1) {
                    plainData = new byte[plainDataSize];
                    commonDataStream.readFully(plainData);
                }
                int nShares = commonDataStream.readInt();
                ConfidentialData[] snapshotShares = null;
                if (nShares != -1) {
                    snapshotShares = new ConfidentialData[nShares];
                    for (int i = 0; i < nShares; i++) {
                        int shareDataSize = commonDataStream.readInt();
                        byte[] sharedData = null;
                        if (shareDataSize != -1) {
                            sharedData = new byte[shareDataSize];
                            commonDataStream.readFully(sharedData);
                        }
                        Commitments commitments = new Commitments();
                        commitments.readExternal(commonDataStream);

                        Share share = recoverShare(currentShares, commitments);

                        if (share == null) {
                            return null;
                        }

                        VerifiableShare vs = new VerifiableShare(share, commitments, sharedData);
                        int nPublicShares = commonDataStream.readInt();
                        LinkedList<VerifiableShare> publicShares = null;

                        if (nPublicShares != -1) {
                            publicShares = new LinkedList<>();
                            while (nPublicShares-- > 0) {
                                VerifiableShare v = new VerifiableShare();
                                v.readExternal(commonDataStream);
                                publicShares.add(v);
                            }
                        }

                        snapshotShares[i] = publicShares == null ?
                                new ConfidentialData(vs) : new ConfidentialData(vs, publicShares);
                    }
                }

                snapshot = snapshotShares == null ?
                        new ConfidentialSnapshot(plainData)
                        : new ConfidentialSnapshot(plainData, snapshotShares);
            }

            int lastCheckpointCID = selectCorrectKey(lastCheckpointCIDSenders);
            int lastCID = selectCorrectKey(lastCIDSenders);
            byte[] serializedState = snapshot == null ? null : snapshot.serialize();
            return new DefaultApplicationState(
                    log,
                    lastCheckpointCID,
                    lastCID,
                    serializedState,
                    serializedState == null ? null : TOMUtil.computeHash(serializedState),
                    pid
            );
        } catch (IOException | ClassNotFoundException e) {
            logger.error("Failed to restore the state", e);
        }

        return null;
    }

    private Share recoverShare(Map<Integer, Iterator<Share>> currentShares, Commitments commitments) {
        try {
            Share[] recoveringShares = new Share[threshold + (corruptedServers < threshold ? 2 : 1)];
            int j = 0;
            Map<Integer, Share> allRecoveringShares = new HashMap<>();
            for (Map.Entry<Integer, Iterator<Share>> entry : currentShares.entrySet()) {
                Share share = entry.getValue().next();
                if (j < recoveringShares.length) {
                    recoveringShares[j++] = share;
                }
                allRecoveringShares.put(entry.getKey(), share);
                entry.getValue().remove();
            }

            Polynomial polynomial = new Polynomial(field, recoveringShares);
            BigInteger shareNumber;
            if (polynomial.getDegree() != threshold) {
                recoveringShares = new Share[threshold + 1];
                Commitments verificationCommitments = commitmentScheme.sumCommitments(transferPolynomialCommitments,
                        commitments);
                for (Map.Entry<Integer, Share> entry : allRecoveringShares.entrySet()) {
                    if (commitmentScheme.checkValidity(entry.getValue(), verificationCommitments)) {
                        recoveringShares[j++] = entry.getValue();
                        if (j == recoveringShares.length)
                            break;
                    } else {
                        logger.error("Server {} sent me invalid share", entry.getKey());
                        currentShares.remove(entry.getKey());
                        recoveryShares.remove(entry.getKey());
                    }
                }
                shareNumber = interpolationStrategy.interpolateAt(shareholderId, recoveringShares);
            } else {
                shareNumber = polynomial.evaluateAt(shareholderId);
            }

            return new Share(shareholderId, shareNumber);
        } catch (SecretSharingException e) {
            logger.debug("Failed to create recovering polynomial");
        }
        return null;
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

        if (max <= threshold) {
            return -1;
        }

        return key;
    }

    private<T> T selectCorrectData(Map<Integer, Integer> dataSenders, Map<Integer, T> data) {
        int max = 0;
        T result = null;

        for (Map.Entry<Integer, Integer> entry : dataSenders.entrySet()) {
            if (entry.getValue() > max) {
                max = entry.getValue();
                result = data.get(entry.getKey());
            }
        }

        if (max <= threshold) {
            return null;
        }

        return result;
    }
}