package confidential.statemanagement;

import bftsmart.statemanagement.ApplicationState;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import confidential.ConfidentialData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.CommitmentScheme;
import vss.commitment.Commitments;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class StateRecoveryHandler2 extends Thread {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private Map<Integer, RecoveryApplicationState> recoveryStates;
    private final int threshold;
    private final BigInteger field;
    private BlockingQueue<RecoverySMMessage> stateQueue;
    private int corruptedServers;

    private CommitmentScheme commitmentScheme;

    private Map<Integer, byte[]> snapshotPlainData;
    private Map<Integer, Integer> snapshotPlainDataSenders;
    private Map<Integer, ConfidentialSnapshot> snapshots;

    private ConfidentialData[] recoveredSnapshotConfidentialData;
    private Map<Integer, Integer> snapshotConfidentialDataSize;
    private int recoveringSnapshotConfidentialDataIndex;
    private boolean snapshotConfidentialDataRecovered;
    private boolean hasConfidentialData;

    private CommandsInfo[] recoveredCommandsInfo;
    private Map<Integer, Integer> commandsInfoSize;
    private int recoveredCommandsInfoIndex;
    private boolean commandsInfoRecovered;
    private boolean hasCommandsInfo;

    private Map<Integer, Commitments> polynomialCommitments;
    private Map<Integer, Integer> polynomialCommitmentsSenders;
    private Commitments transferPolynomialCommitments;

    private Map<Integer, byte[]> sharedData;
    private Map<Integer, Integer> sharedDataSenders;

    private Map<Integer, Integer> lastCheckpointCIDSenders;
    private Map<Integer, Integer> lastCIDSenders;

    private int pid;
    private BigInteger shareholderId;

    public StateRecoveryHandler2(int threshold, int pid, BigInteger field, CommitmentScheme commitmentScheme) {
        super("State Recovery Handler Thread");
        this.threshold = threshold;
        this.pid = pid;
        this.shareholderId = BigInteger.valueOf(pid + 1);
        this.field = field;

        this.commitmentScheme = commitmentScheme;

        this.recoveryStates = new HashMap<>(2 * threshold + 1);
        this.stateQueue = new LinkedBlockingQueue<>();

        this.snapshotPlainData = new HashMap<>(threshold + 1);
        this.snapshotPlainDataSenders = new HashMap<>(threshold + 1);
        this.snapshots = new HashMap<>(2 * threshold + 1);

        this.commandsInfoSize = new HashMap<>(threshold + 1);

        this.sharedData = new HashMap<>(threshold + 1);
        this.sharedDataSenders = new HashMap<>(threshold + 1);

        this.snapshotConfidentialDataSize = new HashMap<>(threshold + 1);

        this.polynomialCommitments = new HashMap<>(threshold + 1);

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
                RecoveryApplicationState state = (RecoveryApplicationState)recoveryMessage.getState();
                recoveryStates.put(recoveryMessage.getSender(), state);

                int sender = recoveryMessage.getSender();

                //to select correct recovery polynomial commitments
                if (transferPolynomialCommitments == null) {
                    int transferPolynomialCommitmentsHashCode = state.getTransferPolynomialCommitments().hashCode();
                    polynomialCommitments.computeIfAbsent(transferPolynomialCommitmentsHashCode,
                            k -> state.getTransferPolynomialCommitments());
                    polynomialCommitmentsSenders.merge(transferPolynomialCommitmentsHashCode,
                            1, Integer::sum);
                }

                //to select correct snapshot plainData and to create array for storing recovered ConfidentialData
                if (state.hasState()) {
                    ConfidentialSnapshot snapshot = ConfidentialSnapshot.deserialize(state.getSerializedState());
                    if (snapshot == null) {
                        logger.error("Failed to deserialize server {} snapshot", sender);
                        logger.error("Removing server {} recovery state", sender);
                        recoveryStates.remove(sender);
                        continue;
                    }

                    int plainDataHashCode = Arrays.hashCode(snapshot.getPlainData());
                    snapshotPlainData.computeIfAbsent(plainDataHashCode, k -> snapshot.getPlainData());
                    snapshotPlainDataSenders.merge(plainDataHashCode, 1, Integer::sum);
                    snapshots.put(sender, snapshot);

                    if (recoveredSnapshotConfidentialData == null && snapshot.getShares() != null) {
                        int size = snapshot.getShares().length;
                        hasConfidentialData = true;
                        snapshotConfidentialDataSize.merge(size, 1, Integer::sum);
                    }
                }

                lastCheckpointCIDSenders.merge(state.getLastCheckpointCID(), 1, Integer::sum);
                lastCIDSenders.merge(state.getLastCID(), 1, Integer::sum);

                //to create array for storing recovered CommandsInfo
                if (recoveredCommandsInfo == null && state.getMessageBatches() != null) {
                    hasCommandsInfo = true;
                    int size = state.getMessageBatches().length;
                    commandsInfoSize.merge(size, 1, Integer::sum);
                }


                //checking if I have enough states to use detection scheme or if I have already identified f faulty servers
                if ((corruptedServers < threshold && recoveryStates.size() < threshold + 2)
                        || (corruptedServers == threshold && recoveryStates.size() <= threshold))
                    continue;

                /*
                 * hasCommandsInfo and hasConfidentialData will have correct value before entering here,
                 * because recoveryStates.size() > threshold, therefore there is at least one correct state
                 */
                if (!(hasCommandsInfo || hasConfidentialData))
                    break;

                if (transferPolynomialCommitments == null)
                    transferPolynomialCommitments = selectCorrectPolynomialCommitments();

                if (hasCommandsInfo && recoveredCommandsInfo == null) {
                    int size = selectCorrectKey(commandsInfoSize);
                    if (size < 0) {
                        continue;
                    }
                    recoveredCommandsInfo = new CommandsInfo[size];
                }

                if (hasConfidentialData && recoveredSnapshotConfidentialData == null) {
                    int size = selectCorrectKey(snapshotConfidentialDataSize);
                    if (size < 0) {
                        continue;
                    }
                    recoveredSnapshotConfidentialData = new ConfidentialData[size];
                }

                /*
                 * At this point:
                 * if hasCommandsInfo == true then recoveredCommandsInfo != null
                 * if hasConfidentialData == true then recoveredSnapshotConfidentialData != null
                 */

                removeFaultyStates();

                /*if (corruptedServers < threshold && (recoveryStates.size() < threshold + 2
                        || (hasConfidentialData && snapshots.size() < threshold + 2)))
                    continue;*/

                if (recoveryStates.size() + corruptedServers < 2 * threshold + 1)
                    continue;

                recoverCommandsInfo();
                recoverSnapshotConfidentialData();

                snapshotConfidentialDataRecovered = !hasConfidentialData
                        || recoveringSnapshotConfidentialDataIndex >= recoveredSnapshotConfidentialData.length;
                commandsInfoRecovered = !hasCommandsInfo
                        || recoveredCommandsInfoIndex >= recoveredCommandsInfo.length;

                if (commandsInfoRecovered && snapshotConfidentialDataRecovered)
                    break;
            } catch (InterruptedException e) {
                logger.error("Failed to poll state from queue", e);
            }
        }

        byte[] recoveredSnapshotPlainData = selectCorrectSnapshotPlainData();
        byte[] recoveredState = null;
        if (recoveredSnapshotPlainData != null) {
            ConfidentialSnapshot recoveredSnapshot = hasConfidentialData ?
                    new ConfidentialSnapshot(recoveredSnapshotPlainData, recoveredSnapshotConfidentialData)
                    : new ConfidentialSnapshot(recoveredSnapshotPlainData);
            recoveredState = recoveredSnapshot.serialize();
        }

        int lastCheckpointCID = selectCorrectKey(lastCheckpointCIDSenders);
        int lastCID = selectCorrectKey(lastCIDSenders);

        ApplicationState state = new DefaultApplicationState(recoveredCommandsInfo, lastCheckpointCID, lastCID,
                recoveredState, TOMUtil.computeHash(recoveredState), pid);

        logger.debug("Exiting state recovery handler thread");
    }

    private void recoverSnapshotConfidentialData() {
        while (recoveringSnapshotConfidentialDataIndex < recoveredSnapshotConfidentialData.length) {
            Share[] shares = new Share[threshold + corruptedServers < threshold ? 2 : 1];
            int j = 0;
            polynomialCommitments.clear();
            polynomialCommitmentsSenders.clear();
            sharedData.clear();
            sharedDataSenders.clear();

            for (Map.Entry<Integer, ConfidentialSnapshot> entry : snapshots.entrySet()) {
                ConfidentialData cd = entry.getValue().getShares()[recoveringSnapshotConfidentialDataIndex];
                VerifiableShare vs = cd.getShare();
                int sharedDataHashCode = Arrays.hashCode(vs.getSharedData());
                sharedData.computeIfAbsent(sharedDataHashCode, k -> vs.getSharedData());
                sharedDataSenders.merge(sharedDataHashCode, 1, Integer::sum);

                int commitmentsHashCode = vs.getCommitments().hashCode();
                polynomialCommitments.computeIfAbsent(commitmentsHashCode, k -> vs.getCommitments());
                polynomialCommitmentsSenders.merge(commitmentsHashCode, 1, Integer::sum);

                shares[j++] = vs.getShare();
                if (j == shares.length)
                    break;
            }

            try {
                Polynomial polynomial = new Polynomial(field, shares);
                Commitments commitments = selectCorrectPolynomialCommitments();
                if (polynomial.getDegree() != threshold) {//found invalid share
                    Commitments transferCommitments = commitmentScheme.sumCommitments(selectCorrectPolynomialCommitments(),
                            transferPolynomialCommitments);
                    Set<Integer> corruptedSenders = new HashSet<>();
                    shares = new Share[threshold + 1];
                    j = 0;
                    for (Map.Entry<Integer, ConfidentialSnapshot> entry : snapshots.entrySet()) {
                        Share share = entry.getValue().getShares()[recoveringSnapshotConfidentialDataIndex]
                                .getShare().getShare();
                        if (!commitmentScheme.checkValidity(share, transferCommitments)) {
                            corruptedSenders.add(entry.getKey());
                            corruptedServers++;
                        } else {
                            if (j < shares.length)
                                shares[j++] = share;
                        }
                    }
                    //removing snapshot and state of faulty servers
                    for (Integer sender : corruptedSenders) {
                        logger.error("Server {} is faulty", sender);
                        snapshots.remove(sender);
                        recoveryStates.remove(sender);
                    }
                    if (j < shares.length) //do not have enough shares
                        return;
                    polynomial = new Polynomial(field, shares);
                }
                BigInteger recoveredShareNumber = polynomial.evaluateAt(shareholderId);
                recoveredSnapshotConfidentialData[recoveringSnapshotConfidentialDataIndex++] = new ConfidentialData(
                        new VerifiableShare(new Share(shareholderId, recoveredShareNumber), commitments, null)
                );
            } catch (SecretSharingException e) {
                logger.error("Failed to create polynomial to restore state.", e);
            }
        }
    }

    private void recoverCommandsInfo() {
    }

    private void removeFaultyStates() {
        Set<Integer> faultySenders = new HashSet<>();
        if (hasCommandsInfo) {
            for (Map.Entry<Integer, RecoveryApplicationState> entry : recoveryStates.entrySet()) {
                if (entry.getValue().getMessageBatches().length != recoveredCommandsInfo.length) {
                    faultySenders.add(entry.getKey());
                }
            }
        }

        if (hasConfidentialData) {
            for (Map.Entry<Integer, ConfidentialSnapshot> entry : snapshots.entrySet()) {
                if (entry.getValue().getPlainData().length != recoveredSnapshotConfidentialData.length)
                    faultySenders.add(entry.getKey());
            }
        }

        for (Integer sender : faultySenders) {
            logger.error("Server {} is faulty", sender);
            recoveryStates.remove(sender);
            snapshots.remove(sender);
            corruptedServers++;
        }
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

    private Commitments selectCorrectPolynomialCommitments() {
        int max = 0;
        Commitments commitments = null;
        for (Map.Entry<Integer, Integer> entry : polynomialCommitmentsSenders.entrySet()) {
            if (entry.getValue() > max) {
                max = entry.getValue();
                commitments = polynomialCommitments.get(entry.getKey());
            }
        }

        return commitments;
    }

    private byte[] selectCorrectSnapshotPlainData() {
        int max = 0;
        byte[] plainData = null;

        for (Map.Entry<Integer, Integer> entry : snapshotPlainDataSenders.entrySet()) {
            if (entry.getValue() > max) {
                max = entry.getValue();
                plainData = snapshotPlainData.get(entry.getKey());
            }
        }

        if (max <= threshold) {
            return null;
        }

        return plainData;
    }
}
