package confidential.statemanagement;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.MessageContext;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import confidential.ConfidentialData;
import confidential.Utils;
import confidential.server.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.interpolation.InterpolationStrategy;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class StateRecoveryHandler extends Thread {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private final int threshold;
    private final BigInteger field;
    private int corruptedServers;

    private CommitmentScheme commitmentScheme;
    private InterpolationStrategy interpolationStrategy;

    private Commitment transferPolynomialCommitments;

    private Map<Integer, Integer> commonData;
    private byte[] selectedCommonData;
    private int selectedCommonDataHash;
    private int nCommonDataReceived;

    private Map<Integer, LinkedList<Share>> recoveryShares;
    private Map<Integer, Integer> recoverySharesSize;
    private int correctRecoverySharesSize;


    private int pid;
    private int stateSenderReplica;
    private BigInteger shareholderId;

    private ObjectInputStream commonDataStream;
    private ReconstructionCompleted reconstructionListener;
    private RecoveryPrivateStateReceiver recoveryPrivateStateReceiver;
    private RecoveryPublicStateReceiver recoveryPublicStateReceiver;
    private Lock lock = new ReentrantLock();
    private Condition condition = lock.newCondition();

    StateRecoveryHandler(ReconstructionCompleted reconstructionListener, int threshold,
                         ServerViewController svController, BigInteger field, CommitmentScheme commitmentScheme,
                         InterpolationStrategy interpolationStrategy, int stateSenderReplica, int serverPort) {
        super("State Recovery Handler Thread");
        this.reconstructionListener = reconstructionListener;
        this.threshold = threshold;
        this.pid = svController.getStaticConf().getProcessId();
        this.stateSenderReplica = stateSenderReplica;
        this.shareholderId = BigInteger.valueOf(pid + 1);
        this.field = field;

        this.commitmentScheme = commitmentScheme;
        this.interpolationStrategy = interpolationStrategy;

        this.commonData = new HashMap<>(threshold + 1);

        this.recoveryShares = new HashMap<>(threshold + 1);
        this.recoverySharesSize = new HashMap<>(threshold + 1);
        this.correctRecoverySharesSize = -1;

        try {
            this.recoveryPrivateStateReceiver = new RecoveryPrivateStateReceiver(this, svController, serverPort);
            this.recoveryPublicStateReceiver = new RecoveryPublicStateReceiver(this, svController, serverPort + 1);
            this.recoveryPrivateStateReceiver.start();
            this.recoveryPublicStateReceiver.start();
        } catch (IOException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException | KeyManagementException e) {
            logger.error("Failed to initialize recovery state receiver threads");
        }
    }


    void deliverPrivateState(int from, LinkedList<Share> privateState) {
        lock.lock();
        recoveryShares.put(from, privateState);
        recoverySharesSize.merge(privateState.size(), 1, Integer::sum);
        condition.signalAll();
        lock.unlock();
    }

    void deliverPublicState(int from, byte[] publicState, byte[] publicStateHash) {
        lock.lock();
        if (commonDataStream == null) {
            int commonDataHashCode = Arrays.hashCode(publicStateHash);
            logger.info("Public state hash {} of server {}", commonDataHashCode, from);
            if (stateSenderReplica == from) {
                selectedCommonData = publicState;
                selectedCommonDataHash = commonDataHashCode;
                logger.info("Replica {} sent me public state of {} bytes", from, selectedCommonData.length);
            } else {
                logger.info("Replica {} sent me hash of the public state", from);
            }
            commonData.merge(commonDataHashCode, 1, Integer::sum);
            nCommonDataReceived++;
            condition.signalAll();
        }
        lock.unlock();
    }

    @Override
    public void run() {
        while (true) {
            try {
                lock.lock();
                condition.await();

                if (recoveryShares.size() < 2 * threshold + 1 || selectedCommonData == null || nCommonDataReceived < 2 * threshold + 1)
                    continue;
                logger.info("I have received 2t+1 recovery states");
                if (commonDataStream == null) {
                    if (haveCorrectCommonData())
                        commonDataStream = new ObjectInputStream(new ByteArrayInputStream(selectedCommonData));
                    else
                        logger.info("I don't have enough same states");
                }
                if (correctRecoverySharesSize == -1)
                    correctRecoverySharesSize = selectCorrectKey(recoverySharesSize);

                if (commonDataStream != null && correctRecoverySharesSize != -1) {
                    logger.info("Reconstructing state");
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
            } finally {
                lock.unlock();
            }
        }
        recoveryPrivateStateReceiver.interrupt();
        recoveryPublicStateReceiver.interrupt();
        logger.debug("Exiting state recovery handler thread");
    }

    private boolean haveCorrectCommonData() {
        if (selectedCommonData == null) //I did not received yet public state
            return false;
        Optional<Map.Entry<Integer, Integer>> max = commonData.entrySet().stream()
                .max(Comparator.comparingInt(Map.Entry::getValue));
        if (!max.isPresent()) {
            logger.info("I don't have correct public state");
            return false;
        }

        Map.Entry<Integer, Integer> entry = max.get();
        if (entry.getValue() < threshold + 1) {
            logger.info("I don't have correct public state");
            return false;
        }
        logger.info("key: {}", entry.getKey());
        return selectedCommonDataHash == entry.getKey();
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
            byte[] nonce;
            if (len != -1) {
                nonce = new byte[len];
                in.readFully(nonce);
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
            transferPolynomialCommitments = Utils.readCommitment(commonDataStream);
            int lastCheckpointCID = commonDataStream.readInt();
            int lastCID = commonDataStream.readInt();
            int logSize = commonDataStream.readInt();
            CommandsInfo[] log = null;
            if (logSize != -1) {
                logger.info("Reconstructing log");
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
                                Commitment commitments = Utils.readCommitment(commonDataStream);

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
                logger.info("Reconstructing snapshot");
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
                        Commitment commitments = Utils.readCommitment(commonDataStream);

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

    private Share recoverShare(Map<Integer, Iterator<Share>> currentShares, Commitment commitments) {
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
                Commitment verificationCommitments = commitmentScheme.sumCommitments(transferPolynomialCommitments,
                        commitments);
                commitmentScheme.startVerification(verificationCommitments);
                for (Map.Entry<Integer, Share> entry : allRecoveringShares.entrySet()) {
                    if (commitmentScheme.checkValidity(entry.getValue(), verificationCommitments)) {
                        recoveringShares[j++] = entry.getValue();
                        //if (j == recoveringShares.length)
                            //break;
                    } else {
                        logger.error("Server {} sent me invalid share", entry.getKey());
                        currentShares.remove(entry.getKey());
                        recoveryShares.remove(entry.getKey());
                        corruptedServers++;
                    }
                }
                commitmentScheme.endVerification();
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
}
