package confidential.statemanagement.privatestate.receiver;

import bftsmart.reconfiguration.ServerViewController;
import confidential.Configuration;
import confidential.server.ServerConfidentialityScheme;
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

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public abstract class BlindedStateHandler extends Thread {
    protected final Logger logger = LoggerFactory.getLogger("state_transfer");
    protected final BigInteger shareholderId;
    protected final BigInteger field;
    private final StateReceivedListener stateReceivedListener;
    protected final AtomicInteger corruptedServers;
    protected final int f;
    private final int quorum;
    private final int stateSenderReplica;
    protected final ServerConfidentialityScheme confidentialityScheme;
    protected final CommitmentScheme commitmentScheme;
    protected final InterpolationStrategy interpolationStrategy;
    private final BlindedCommitmentHandler commitmentsHandler;

    private final Lock lock;
    private final Condition waitingBlindedDataCondition;

    protected final Set<Integer> stillValidSenders;

    private final Map<Integer, Integer> commonState;
    private byte[] selectedCommonState;
    private int selectedCommonStateHash;
    private byte[] correctCommonState;
    private int nCommonStateReceived;

    private final Map<Integer, Share[]> allBlindedShares;
    private final Map<Integer, Integer> blindedSharesSize;
    private int correctBlindedSharesSize;
    private final BlindedDataReceiver blindedDataReceiver;

    public BlindedStateHandler(ServerViewController svController, int serverPort, int f, int quorum,
                               int stateSenderReplica, ServerConfidentialityScheme confidentialityScheme,
                               StateReceivedListener stateReceivedListener) {
        super("Blinded State Handler Thread");
        int pid = svController.getStaticConf().getProcessId();
        this.shareholderId = confidentialityScheme.getMyShareholderId();
        this.field = confidentialityScheme.getField();
        this.stateReceivedListener = stateReceivedListener;
        this.corruptedServers = new AtomicInteger(0);
        this.f = f;
        this.quorum = quorum;
        this.stateSenderReplica = stateSenderReplica;
        this.confidentialityScheme = confidentialityScheme;
        this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
        this.interpolationStrategy = confidentialityScheme.getInterpolationStrategy();
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
            blindedDataReceiver = new BlindedDataReceiver(this, svController,
                    port, quorum, stateSenderReplica);
            blindedDataReceiver.start();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to initialize blinded data receiver thread", e);
        }
    }

    @Override
    public void interrupt() {
        blindedDataReceiver.shutdown();
        blindedDataReceiver.interrupt();
        super.interrupt();
    }

    public void deliverBlindedData(int from, byte[][] shares, byte[] serializedCommonState, byte[] commonStateHash,
                                   Commitment[] commitments, byte[] commitmentsHash) {
        lock.lock();
        logger.debug("Received blinded data from {}", from);
        int commonStateHashCode = Arrays.hashCode(commonStateHash);
        if (from == stateSenderReplica) {
            selectedCommonState = serializedCommonState;
            selectedCommonStateHash = commonStateHashCode;
            logger.debug("Replica {} sent me a common state of {} bytes", from,
                    serializedCommonState == null ? "null" : serializedCommonState.length);
        } else {
            logger.debug("Replica {} sent me common state hash", from);
        }

        commonState.merge(commonStateHashCode, 1, Integer::sum);

        commitmentsHandler.handleNewCommitments(from, commitments, commitmentsHash);

        nCommonStateReceived++;

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

    protected abstract LinkedList<VerifiableShare> reconstructShares(int nShares,
                                                                   Map<Integer, Share[]> allBlindedShares,
                                                                   Map<BigInteger, Commitment[]> allBlindedCommitments);

    @Override
    public void run() {
        while (true) {
            try {
                lock.lock();
                logger.debug("Processing new blinded data");
                if (allBlindedShares.size() <= f + 1 || selectedCommonState == null || nCommonStateReceived <= f) {
                    logger.debug("Waiting for more state: {} <= {} | selectedCommonState={} | {} <= {}",
                            allBlindedShares.size(), f + 1, selectedCommonState == null ? "null" : "not null",
                            nCommonStateReceived, f + 1);
                    waitingBlindedDataCondition.await();
                    continue;
                } else {
                    logger.debug("I have the minimum number of blinded shares, common state and common state hashes");
                }
                if (correctCommonState == null) {
                    if (haveCorrectState(selectedCommonState, commonState, selectedCommonStateHash)) {
                        correctCommonState = selectedCommonState;
                    } else {
                        logger.debug("I don't have enough same common states");
                        waitingBlindedDataCondition.await();
                        continue;
                    }
                }

                if (!commitmentsHandler.prepareCommitments()) {
                    logger.debug("Commitments are not prepared");
                    waitingBlindedDataCondition.await();
                    continue;
                }

                if (correctBlindedSharesSize == -1) {
                    correctBlindedSharesSize = selectCorrectKey(blindedSharesSize);
                    logger.debug("Correct blinded shares size is {}", correctBlindedSharesSize);
                }

                if (correctCommonState != null && correctBlindedSharesSize != -1) {
                    logger.debug("Reconstructing state");
                    long startTime = System.nanoTime();
                    LinkedList<VerifiableShare> reconstructedShares = reconstructPrivateState();
                    long endTime = System.nanoTime();
                    double totalTime = (endTime - startTime) / 1_000_000.0;
                    logger.info("Took {} ms to reconstruct shares [{} shares]", totalTime, reconstructedShares.size());
                    stateReceivedListener.onStateReceived(correctCommonState, reconstructedShares);
                    break;
                } else {
                    logger.debug("correctBlindedSharesSize={}", correctBlindedSharesSize);
                }

            } catch (InterruptedException e) {
                //logger.error("Failed to reconstruct private state", e);
                break;
            } finally {
                lock.unlock();
            }
        }
        blindedDataReceiver.shutdown();
        blindedDataReceiver.interrupt();
        logger.debug("Exiting blinded state handler thread");
    }

    private LinkedList<VerifiableShare> reconstructPrivateState() {
        //Collecting all commitments
        Set<BigInteger> validShareholders = new HashSet<>(stillValidSenders.size());
        for (Integer validSender : stillValidSenders) {
            validShareholders.add(confidentialityScheme.getShareholder(validSender));
        }

        Map<BigInteger, Commitment[]> allBlindedCommitments = commitmentsHandler.readAllCommitments(validShareholders);

        return reconstructShares(correctBlindedSharesSize, allBlindedShares,
                allBlindedCommitments);
    }


    private boolean haveCorrectState(byte[] selectedState, Map<Integer, Integer> states,
                                     int selectedStateHash) {
        if (selectedState == null)
            return false;
        Optional<Map.Entry<Integer, Integer>> max = states.entrySet().stream()
                .max(Comparator.comparingInt(Map.Entry::getValue));
        if (!max.isPresent()) {
            logger.debug("I don't have correct common state");
            return false;
        }
        Map.Entry<Integer, Integer> entry = max.get();
        if (entry.getValue() <= f) {
            logger.debug("I don't have correct common state");
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


}
