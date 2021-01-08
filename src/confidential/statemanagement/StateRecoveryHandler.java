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
import confidential.Configuration;
import confidential.server.Request;
import confidential.server.ServerConfidentialityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.Utils;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class StateRecoveryHandler extends Thread {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private final int threshold;
    private final BigInteger field;
    private final AtomicInteger corruptedServers;
    private final int quorum;

    private final CommitmentScheme commitmentScheme;
    private final InterpolationStrategy interpolationStrategy;

    private Commitment transferPolynomialCommitments;

    private final Map<Integer, Integer> commonData;
    private byte[] selectedCommonData;
    private int selectedCommonDataHash;
    private int nCommonDataReceived;
    private final Map<Integer, ObjectInputStream> commitmentsBytes;

    private final Map<Integer, LinkedList<Share>> recoveryShares;
    private final Map<Integer, Integer> recoverySharesSize;
    private int correctRecoverySharesSize;


    private final int pid;
    private final ServerConfidentialityScheme confidentialityScheme;
    private final int stateSenderReplica;
    private final BigInteger shareholderId;

    private ObjectInputStream commonDataStream;
    private final ReconstructionCompleted reconstructionListener;
    private RecoveryPrivateStateReceiver recoveryPrivateStateReceiver;
    private RecoveryPublicStateReceiver recoveryPublicStateReceiver;
    private final Lock lock = new ReentrantLock();
    private final Condition condition = lock.newCondition();

    StateRecoveryHandler(ReconstructionCompleted reconstructionListener, int threshold,
                         ServerViewController svController, BigInteger field,
                         ServerConfidentialityScheme confidentialityScheme,
                         int stateSenderReplica, int serverPort) {
        super("State Recovery Handler Thread");
        this.reconstructionListener = reconstructionListener;
        this.threshold = threshold;
        this.quorum = 2 * threshold + 1;
        this.pid = svController.getStaticConf().getProcessId();
        this.confidentialityScheme = confidentialityScheme;
        this.stateSenderReplica = stateSenderReplica;
        this.shareholderId = confidentialityScheme.getMyShareholderId();
        this.field = field;
        this.corruptedServers = new AtomicInteger(0);
        this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
        this.interpolationStrategy = confidentialityScheme.getInterpolationStrategy();

        this.commonData = new HashMap<>(quorum);
        this.commitmentsBytes = new HashMap<>(quorum);
        this.recoveryShares = new HashMap<>(quorum);
        this.recoverySharesSize = new HashMap<>(quorum);
        this.correctRecoverySharesSize = -1;

        try {
            this.recoveryPrivateStateReceiver =
                    new RecoveryPrivateStateReceiver(this, svController, serverPort);
            this.recoveryPublicStateReceiver =
                    new RecoveryPublicStateReceiver(this, svController, serverPort + 1);
            this.recoveryPrivateStateReceiver.start();
            this.recoveryPublicStateReceiver.start();
        } catch (Exception e) {
            logger.error("Failed to initialize recovery state receiver threads", e);
        }
    }


    void deliverPrivateState(int from, LinkedList<Share> privateState) {
        lock.lock();
        recoveryShares.put(from, privateState);
        recoverySharesSize.merge(privateState.size(), 1, Integer::sum);
        condition.signalAll();
        lock.unlock();
    }

    void deliverPublicState(int from, byte[] publicState, byte[] publicStateHash, byte[] commitments) {
        lock.lock();
        if (commonDataStream == null) {
            int commonDataHashCode = Arrays.hashCode(publicStateHash);
            logger.debug("Public state hash {} of server {}", commonDataHashCode, from);
            if (stateSenderReplica == from) {
                selectedCommonData = publicState;
                selectedCommonDataHash = commonDataHashCode;
                logger.debug("Replica {} sent me public state of {} bytes", from, selectedCommonData.length);
            } else {
                logger.debug("Replica {} sent me hash of the public state", from);
            }
            commonData.merge(commonDataHashCode, 1, Integer::sum);
            try {
                commitmentsBytes.put(from,
                        new ObjectInputStream(new ByteArrayInputStream(commitments)));
            } catch (IOException e) {
                logger.error("Failed open stream to read commitments from {}", from);
            }
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
                if (recoveryShares.size() < quorum || selectedCommonData == null
                        || nCommonDataReceived < quorum || commitmentsBytes.size() < quorum)
                    continue;
                logger.debug("I have received 2t+1 recovery states");
                if (commonDataStream == null) {
                    if (haveCorrectCommonData())
                        commonDataStream = new ObjectInputStream(new ByteArrayInputStream(selectedCommonData));
                    else
                        logger.debug("I don't have enough same states");
                }
                if (correctRecoverySharesSize == -1)
                    correctRecoverySharesSize = selectCorrectKey(recoverySharesSize);

                if (commonDataStream != null && correctRecoverySharesSize != -1) {
                    logger.info("Reconstructing state");
                    long startTime = System.nanoTime();
                    DefaultApplicationState recoveredState = recoverState();
                    long endTime = System.nanoTime();
                    double totalTime = (endTime - startTime) / 1_000_000.0;
                    logger.info("Took {} ms to recover state", totalTime);
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
            logger.debug("I don't have correct public state");
            return false;
        }

        Map.Entry<Integer, Integer> entry = max.get();
        if (entry.getValue() < threshold + 1) {
            logger.debug("I don't have correct public state");
            return false;
        }
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
                    proof, firstInBatch, noOp, metadata);
            if (lastInBatch)
                messageContext.setLastInBatch();
            messageContexts[i] = messageContext;
        }

        return messageContexts;
    }

    private DefaultApplicationState recoverState() {
        try {
            int nS = -1;

            //Collecting all blinded shares
            Map<Integer, Share[]> allBlindedShares = new HashMap<>(recoveryShares.size());
            Share[] shareTemp;
            for (Map.Entry<Integer, LinkedList<Share>> entry : recoveryShares.entrySet()) {
                int i = 0;
                if (nS == -1) {
                    nS = entry.getValue().size();
                }
                shareTemp = new Share[nS];
                for (Share share : entry.getValue()) {
                    shareTemp[i++] = share;
                }
                allBlindedShares.put(entry.getKey(), shareTemp);
            }

            //Collecting all commitments
            Map<BigInteger, Commitment> allTransferPolynomialCommitments = nextCommitment();
            transferPolynomialCommitments = commitmentScheme.combineCommitments(allTransferPolynomialCommitments);

            Map<BigInteger, Commitment[]> allCommitments = new HashMap<>(recoveryShares.size());
            Commitment[] commitmentTemp;
            Map<BigInteger, Commitment> commitments;
            for (int i = 0; i < nS; i++) {
                commitments = nextCommitment();
                for (Map.Entry<BigInteger, Commitment> commitment : commitments.entrySet()) {
                    commitmentTemp = allCommitments.get(commitment.getKey());
                    if (commitmentTemp == null) {
                        commitmentTemp = new Commitment[nS];
                        allCommitments.put(commitment.getKey(), commitmentTemp);
                    }
                    commitmentTemp[i] = commitment.getValue();
                }
            }

            long t1, t2;
            t1 = System.nanoTime();
            Iterator<VerifiableShare> recoveredShares = recoverShares(nS, allBlindedShares, allCommitments);
            t2 = System.nanoTime();
            if (recoveredShares == null) {
                logger.error("Failed to recover shares");
                return null;
            }
            double duration = (t2 - t1) / 1_000_000.0;
            logger.info("Took {} ms to recover {} shares", duration, nS);

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

                                VerifiableShare vs = recoveredShares.next();
                                recoveredShares.remove();
                                vs.setSharedData(sharedData);

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

                        VerifiableShare vs = recoveredShares.next();
                        recoveredShares.remove();
                        vs.setSharedData(sharedData);

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
        } catch (IOException | ClassNotFoundException | InterruptedException e) {
            logger.error("Failed to restore the state", e);
        }

        return null;
    }

    private Iterator<VerifiableShare> recoverShares(int nShares, Map<Integer, Share[]> allBlindedShares,
                                                    Map<BigInteger, Commitment[]> allCommitments)
            throws InterruptedException {
        ExecutorService executorService = Executors
                .newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        VerifiableShare[] recoveredShares = new VerifiableShare[nShares];
        CountDownLatch shareProcessingCounter = new CountDownLatch(nShares);
        Integer[] servers = new Integer[allBlindedShares.size()];
        BigInteger[] shareholders = new BigInteger[allCommitments.size()];
        int k = 0;
        //Load share senders
        for (Integer server : allBlindedShares.keySet()) {
            servers[k++] = server;
        }
        k = 0;
        //Load commitments senders
        for (BigInteger shareholder : allCommitments.keySet()) {
            shareholders[k++] = shareholder;
        }

        for (int i = 0; i < nShares; i++) {
            int finalI = i;
            Map<Integer, Share> blindedShares = new HashMap<>(allBlindedShares.size());
            Map<BigInteger, Commitment> commitments = new HashMap<>(allCommitments.size());
            for (Integer server : servers) {
                blindedShares.put(server, allBlindedShares.get(server)[i]);
            }
            for (BigInteger shareholder : shareholders) {
                commitments.put(shareholder, allCommitments.get(shareholder)[i]);
            }

            executorService.execute(() -> {
                VerifiableShare vs = recoverShare(blindedShares, commitments);
                if (vs == null) {
                    return;
                }
                recoveredShares[finalI] = vs;
                shareProcessingCounter.countDown();
            });
        }

        shareProcessingCounter.await();
        executorService.shutdown();
        LinkedList<VerifiableShare> result = new LinkedList<>();
        for (VerifiableShare refreshedShare : recoveredShares) {
            if (refreshedShare == null)
                return null;
            result.add(refreshedShare);
        }
        return result.iterator();
    }

    private VerifiableShare recoverShare(Map<Integer, Share> allBlindedShares,
                                         Map<BigInteger, Commitment> allCommitments) {
        try {
            int corruptedServers = this.corruptedServers.get();
            Share[] recoveringShares = new Share[threshold + (corruptedServers < threshold ? 2 : 1)];
            int j = 0;
            for (Map.Entry<Integer, Share> entry : allBlindedShares.entrySet()) {
                Share share = entry.getValue();
                if (j < recoveringShares.length) {
                    recoveringShares[j++] = share;
                }
            }

            Polynomial polynomial = new Polynomial(field, recoveringShares);
            BigInteger shareNumber;
            Map<BigInteger, Commitment> validCommitments;

            if (polynomial.getDegree() != threshold) {
                recoveringShares = new Share[threshold + 1];
                validCommitments = new HashMap<>(threshold);
                Commitment combinedCommitment =
                        commitmentScheme.combineCommitments(allCommitments);
                Commitment verificationCommitments = commitmentScheme.sumCommitments(transferPolynomialCommitments,
                        combinedCommitment);
                commitmentScheme.startVerification(verificationCommitments);
                j = 0;
                Set<Integer> invalidServers = new HashSet<>(threshold);
                for (Map.Entry<Integer, Share> entry : allBlindedShares.entrySet()) {
                    int server = entry.getKey();
                    BigInteger shareholder = confidentialityScheme.getShareholder(server);
                    if (commitmentScheme.checkValidity(entry.getValue(), verificationCommitments)) {
                        recoveringShares[j++] = entry.getValue();
                        //if (j == recoveringShares.length)
                            //break;
                        if (validCommitments.size() <= threshold) {
                            validCommitments.put(shareholder, allCommitments.get(shareholder));
                        }
                    } else {
                        logger.error("Server {} sent me invalid share", server);
                        allCommitments.remove(shareholder);
                        this.corruptedServers.incrementAndGet();
                        invalidServers.add(server);
                    }
                }
                commitmentScheme.endVerification();

                for (Integer server : invalidServers) {
                    allBlindedShares.remove(server);
                }

                shareNumber = interpolationStrategy.interpolateAt(shareholderId, recoveringShares);
            } else {
                shareNumber = polynomial.evaluateAt(shareholderId);
                int minNumberOfCommitments = corruptedServers >= threshold ? threshold :
                        threshold + 1;
                validCommitments = new HashMap<>(minNumberOfCommitments);

                for (Share recoveringShare : recoveringShares) {
                    validCommitments.put(recoveringShare.getShareholder(),
                            allCommitments.get(recoveringShare.getShareholder()));
                    if (validCommitments.size() == minNumberOfCommitments)
                        break;
                }
            }

            Commitment commitment;
            try {
                commitment = commitmentScheme.recoverCommitment(shareholderId,
                        validCommitments);
            } catch (SecretSharingException e) { //there is/are invalid witness(es)
                Commitment combinedCommitment =
                        commitmentScheme.combineCommitments(allCommitments);
                Commitment verificationCommitments = commitmentScheme.sumCommitments(transferPolynomialCommitments,
                        combinedCommitment);
                validCommitments.clear();
                commitmentScheme.startVerification(verificationCommitments);
                for (Map.Entry<Integer, Share> entry : allBlindedShares.entrySet()) {
                    int server = entry.getKey();
                    BigInteger shareholder = confidentialityScheme.getShareholder(server);
                    if (commitmentScheme.checkValidity(entry.getValue(), verificationCommitments)) {
                        validCommitments.put(shareholder, allCommitments.get(shareholder));
                        if (validCommitments.size() == threshold)
                            break;
                    } else {
                        logger.error("Server {} sent me invalid commitment", server);
                        this.corruptedServers.incrementAndGet();
                    }
                }
                commitmentScheme.endVerification();
                commitment = commitmentScheme.recoverCommitment(shareholderId,
                        validCommitments);
            }

            Share share = new Share(shareholderId, shareNumber);
            return new VerifiableShare(share, commitment, null);
        } catch (SecretSharingException e) {
            logger.error("Failed to create recovering polynomial", e);
        }
        return null;
    }

    private Map<BigInteger, Commitment> nextCommitment() throws IOException, ClassNotFoundException {
        Map<BigInteger, Commitment> commitments =
                new HashMap<>(commitmentsBytes.size());

        for (Map.Entry<Integer, ObjectInputStream> entry : commitmentsBytes.entrySet()) {
            Commitment commitment = Utils.readCommitment(entry.getValue());
            BigInteger shareholder =
                    confidentialityScheme.getShareholder(entry.getKey());
            commitments.put(shareholder, commitment);
        }

        return commitments;
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
