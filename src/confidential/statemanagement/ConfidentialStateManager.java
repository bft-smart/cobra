package confidential.statemanagement;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.SMMessage;
import bftsmart.statemanagement.StateManager;
import bftsmart.tom.core.DeliveryThread;
import bftsmart.tom.core.TOMLayer;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import confidential.ConfidentialData;
import confidential.polynomial.DistributedPolynomial;
import confidential.polynomial.PolynomialContext;
import confidential.polynomial.PolynomialCreationListener;
import confidential.polynomial.PolynomialCreationReason;
import confidential.server.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.CommitmentScheme;
import vss.commitment.Commitments;
import vss.interpolation.InterpolationStrategy;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

public class ConfidentialStateManager extends StateManager implements PolynomialCreationListener, ReconstructionCompleted {
    private static final long REFRESH_PERIOD = 90_000;
    private static final boolean RENEWAL = false;
    private static final int SERVER_STATE_LISTENING_PORT = 5000;
    private Logger logger = LoggerFactory.getLogger("confidential");
    private final static long INIT_TIMEOUT = 220000;
    private DistributedPolynomial distributedPolynomial;
    private CommitmentScheme commitmentScheme;
    private InterpolationStrategy interpolationStrategy;
    private Timer stateTimer;
    private long timeout = INIT_TIMEOUT;
    private ReentrantLock lockTimer;
    private AtomicInteger sequenceNumber;
    private Map<Integer, SMMessage> onGoingRecoveryRequests;
    private HashMap<Integer, Integer> sequenceNumbers;
    private Timer refreshTimer;
    private TimerTask refreshTriggerTask;
    private StateRecoveryHandler stateRecoveryHandlerThread;
    private long recoveryStartTime;
    private long renewalStartTime;
    private Set<Integer> usedReplicas;

    public ConfidentialStateManager() {
        lockTimer = new ReentrantLock();
        sequenceNumber = new AtomicInteger();
        onGoingRecoveryRequests = new HashMap<>();
        sequenceNumbers = new HashMap<>();
        refreshTimer = new Timer("Refresh Timer");
        usedReplicas = new HashSet<>();
    }

    public void setDistributedPolynomial(DistributedPolynomial distributedPolynomial) {
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RECOVERY);
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RESHARING);
        this.distributedPolynomial = distributedPolynomial;
        if (RENEWAL) {
            setRefreshTimer();
            logger.info("Renewal is active");
        } else
            logger.info("Renewal is deactivated");
    }

    public void setInterpolationStrategy(InterpolationStrategy interpolationStrategy) {
        this.interpolationStrategy = interpolationStrategy;
    }

    public void setCommitmentScheme(CommitmentScheme commitmentScheme) {
        this.commitmentScheme = commitmentScheme;
    }

    @Override
    public void init(TOMLayer tomLayer, DeliveryThread dt) {
        super.init(tomLayer, dt);
        tomLayer.requestsTimer.Enabled(false);
    }

    private int getRandomReplica() {
        int[] processes = SVController.getCurrentViewOtherAcceptors();
        Random rnd = new Random();
        while (true) {
            int i = rnd.nextInt(processes.length);
            int replica = processes[i];
            if (!usedReplicas.contains(replica)) {
                usedReplicas.add(replica);
                return replica;
            }
        }
    }


    @Override
    protected void requestState() {
        logger.debug("requestState");
        recoveryStartTime = System.nanoTime();

        if (tomLayer.requestsTimer != null)
            tomLayer.requestsTimer.clearAll();

        int stateSenderReplica = getRandomReplica();

        DefaultSMMessage recoverySMMessage = new DefaultSMMessage(
                SVController.getStaticConf().getProcessId(),
                waitingCID,
                TOMUtil.SM_REQUEST,
                null,
                SVController.getCurrentView(),
                -1,
                tomLayer.execManager.getCurrentLeader(),
                stateSenderReplica,
                SERVER_STATE_LISTENING_PORT
        );

        logger.info("Replica {} will send full state", stateSenderReplica);
        logger.info("Sending request for state up to CID {} to {}", waitingCID,
                Arrays.toString(SVController.getCurrentViewOtherAcceptors()));
        tomLayer.getCommunication().send(SVController.getCurrentViewOtherAcceptors(), recoverySMMessage);

        tomLayer.requestsTimer.Enabled(false);

        TimerTask stateTask = new TimerTask() {
            @Override
            public void run() {
                logger.info("Timeout to retrieve state");
                SMMessage message = new DefaultSMMessage(
                        SVController.getStaticConf().getProcessId(),
                        waitingCID,
                        TOMUtil.TRIGGER_SM_LOCALLY,
                        null,
                        null,
                        -1,
                        -1,
                        -1,
                        -1
                );
                triggerTimeout(message);
            }
        };

        stateRecoveryHandlerThread = new StateRecoveryHandler(
                this,
                SVController.getCurrentViewF(),
                SVController,
                distributedPolynomial.getField(),
                commitmentScheme,
                interpolationStrategy,
                stateSenderReplica,
                SERVER_STATE_LISTENING_PORT
        );
        stateRecoveryHandlerThread.start();

        stateTimer = new Timer("State Timer");
        timeout *= 2;
        stateTimer.schedule(stateTask, timeout);
    }

    @Override
    public void stateTimeout() {
        lockTimer.lock();
        logger.debug("Timeout for the replicas that were supposed to send the state. Trying again");
        if (stateTimer != null) {
            stateTimer.cancel();
        }
        reset();
        requestState();
        lockTimer.unlock();
    }

    @Override
    public void SMRequestDeliver(SMMessage msg, boolean isBFT) {
        if (msg instanceof DefaultSMMessage) {
            logger.debug("Received recovery request from {}", msg.getSender());
            if (SVController.getStaticConf().isStateTransferEnabled() && dt.getRecoverer() != null) {
                int id = sequenceNumber.getAndIncrement();
                onGoingRecoveryRequests.put(id, msg);
                PolynomialContext context = new PolynomialContext(
                        id,
                        SVController.getCurrentViewF(),
                        BigInteger.valueOf(msg.getSender() + 1),
                        BigInteger.ZERO,
                        SVController.getCurrentViewAcceptors(),
                        msg.getLeader(),
                        PolynomialCreationReason.RECOVERY
                );
                logger.debug("Starting creation of new polynomial with id {} to recover member {}", id, msg.getSender());
                distributedPolynomial.createNewPolynomial(context);

            }
        } else
            logger.warn("Received unknown SM message type from {}", msg.getSender());
    }

    @Override
    public void SMReplyDeliver(SMMessage msg, boolean isBFT) {
        try {
            lockTimer.lock();
            //RecoverySMMessage recoverySMMessage = (RecoverySMMessage)msg;
            RecoveryStateServerSMMessage recoverySMMessage = (RecoveryStateServerSMMessage)msg;
            //logger.info("{} sent me state up to cid {}", msg.getSender(), msg.getCID());
            //logger.debug("waitingCID: {}" , waitingCID);
            sequenceNumbers.merge(recoverySMMessage.getSequenceNumber(), 1, Integer::sum);
            if (!SVController.getStaticConf().isStateTransferEnabled())
                return;

            if (waitingCID == -1 || msg.getCID() != waitingCID) {
                logger.debug("I am not waiting for state or state contains different cid. WaitingCID: {} RequestCID: {}",
                        waitingCID, msg.getCID());
                return;
            }
            if (!appStateOnly) {
                senderRegencies.put(msg.getSender(), msg.getRegency());
                senderLeaders.put(msg.getSender(), msg.getLeader());
                senderViews.put(msg.getSender(), msg.getView());
            }
        } finally {
            lockTimer.unlock();
        }
    }

    /**
     * This method will be called after state is reconstructed, which means that this server already
     * have received f + 1 correct recovery states
     * @param recoveredState Recovered State
     */
    @Override
    public void onReconstructionCompleted(DefaultApplicationState recoveredState) {
        try {
            lockTimer.lock();

            int currentRegency;
            int currentLeader;
            View currentView;

            if (!appStateOnly) {
                Integer temp = getCurrentValue(senderRegencies);
                currentRegency = temp == null ? -1 : temp;
                temp = getCurrentValue(senderLeaders);
                currentLeader = temp == null ? -1 : temp;
                currentView = getCurrentValue(senderViews);
            } else {
                currentLeader = tomLayer.execManager.getCurrentLeader();
                currentRegency = tomLayer.getSynchronizer().getLCManager().getLastReg();
                currentView = SVController.getCurrentView();
            }

            if (currentRegency == -1 || currentLeader == -1 || currentView == null) {
                if (SVController.getCurrentViewN() - SVController.getCurrentViewF() <= getReplies()) {
                    logger.info("currentRegency or currentLeader or currentView are -1 or null");
                    if (stateTimer != null)
                        stateTimer.cancel();
                    reset();
                    requestState();
                    return;
                } else {
                    logger.info("Waiting for more than {} states", SVController.getQuorum());
                    return;
                }
            }

            logger.info("More than f states confirmed");

            if (stateTimer != null)
                stateTimer.cancel();

            tomLayer.getSynchronizer().getLCManager().setLastReg(currentRegency);
            tomLayer.getSynchronizer().getLCManager().setNextReg(currentRegency);
            tomLayer.getSynchronizer().getLCManager().setNewLeader(currentLeader);
            tomLayer.execManager.setNewLeader(currentLeader);

            logger.info("currentRegency: {} currentLeader: {} currentViewId: {}", currentRegency,
                    currentLeader, currentView.getId());

            // I might have timed out before invoking the state transfer, so
            // stop my re-transmission of STOP messages for all regencies up to the current one
            if (currentRegency > 0) {
                logger.debug("Removing STOP retransmissions up to regency {}", currentRegency);
                tomLayer.getSynchronizer().removeSTOPretransmissions(currentRegency - 1);
            }
            //if (currentRegency > 0)
            //    tomLayer.requestsTimer.setTimeout(tomLayer.requestsTimer.getTimeout() * (currentRegency * 2));

            logger.info("Restoring state");
            int seqNumber = getCorrectValue(sequenceNumbers);
            if (seqNumber == -1) {
                logger.error("Sequence numbers are different");
                reset();
                requestState();
                return;
            }

            sequenceNumber.set(seqNumber);

            state = recoveredState;

            if (state == null) {
                logger.error("Failed to reconstruct state. Retrying");
                reset();
                requestState();
                return;
            }
            logger.info("State reconstructed");

            dt.deliverLock();


            logger.info("Updating state");
            dt.update(state);

            logger.info("Last exec: {}", tomLayer.getLastExec());

            if (!appStateOnly && execManager.stopped()) {
                Queue<ConsensusMessage> stoppedMsgs = execManager.getStoppedMsgs();
                for (ConsensusMessage stopped : stoppedMsgs) {
                    if (stopped.getNumber() > state.getLastCID() /*msg.getCID()*/) {
                        execManager.addOutOfContextMessage(stopped);
                    }
                }
                logger.debug("Clear Stopped");
                execManager.clearStopped();
                execManager.restart();
            }

            logger.debug("Processing out of context messages");
            tomLayer.processOutOfContext();
            logger.debug("Finished processing out of context messages");

            if (SVController.getCurrentViewId() != currentView.getId()) {
                logger.info("Installing current view!");
                SVController.reconfigureTo(currentView);
            }

            isInitializing = false;

            waitingCID = -1;

            dt.canDeliver();
            dt.deliverUnlock();

            reset();

            logger.info("I updated the state!");
            tomLayer.requestsTimer.clearAll();
            tomLayer.requestsTimer.Enabled(true);
            //tomLayer.requestsTimer.startTimer();

            if (appStateOnly) {
                appStateOnly = false;
                tomLayer.getSynchronizer().resumeLC();
            }
        } finally {
            lockTimer.unlock();
            long recoveryEndTime = System.nanoTime();
            double totalTime = (recoveryEndTime - recoveryStartTime) / 1_000_000.0;
            logger.info("Recovery duration: {} ms", totalTime);
        }
    }

    private int getCorrectValue(HashMap<Integer, Integer> senders) {
        int max = 0;
        int result = 0;
        for (Map.Entry<Integer, Integer> entry : senders.entrySet()) {
            if (entry.getValue() > max) {
                max = entry.getValue();
                result = entry.getKey();
            }
        }
        if (max <= SVController.getCurrentViewF())
            return -1;
        return result;
    }

    private<T> T getCurrentValue(HashMap<Integer, T> senderValues) {
        Map<T, Integer> counter = new HashMap<>();
        for (T value : senderValues.values()) {
            counter.merge(value, 1, Integer::sum);
        }

        int max = 0;
        T result = null;
        for (Map.Entry<T, Integer> entry : counter.entrySet()) {
            if (entry.getValue() > max) {
                max = entry.getValue();
                result = entry.getKey();
            }
        }
        if (max <= SVController.getCurrentViewF())
            return null;
        return result;
    }

    @Override
    public void onPolynomialCreation(PolynomialContext context, VerifiableShare point, int consensusId) {
        logger.debug("Received my point for {} with id {}", context.getReason(), context.getId());
        if (sequenceNumber.get() <= context.getId())
            sequenceNumber.set(context.getId() + 1);
        if (SVController.getStaticConf().isStateTransferEnabled() && dt.getRecoverer() != null
                && context.getReason() == PolynomialCreationReason.RECOVERY) {
            if (onGoingRecoveryRequests.containsKey(context.getId()))
                sendRecoveryState((DefaultSMMessage)onGoingRecoveryRequests.remove(context.getId()), point);
            else
                logger.debug("There is no recovery request for id {}", context.getId());
        } else if (PolynomialCreationReason.RESHARING == context.getReason()) {
            refreshTriggerTask.cancel();
            long endTime = System.nanoTime() - renewalStartTime;
            logger.info("Renewal polynomial duration: {} ms", (endTime / 1_000_000.0));
            long start = System.nanoTime();
            refreshState(point, consensusId);
            long end = System.nanoTime() - start;
            logger.info("Renewal duration: {} ms", (end / 1_000_000.0));
        }
    }

    private void refreshState(VerifiableShare point, int consensusId) {
        try {
            logger.debug("Renewing my state");

            /*logger.info("Stopping execution manager");
            tomLayer.execManager.stop();
            int lastExec = tomLayer.getLastExec();
            int inExec = tomLayer.getInExec();
*/
            //waitingCID = consensusId;// will make DeliveryThread to stop waiting for state
            dt.iAmWaitingForDeliverLock();
            logger.debug("Trying to acquire deliverLock");
            dt.deliverLock();
            logger.debug("deliverLock acquired");
            dt.iAmNotWaitingForDeliverLock();
            //waitingCID = -1;

            /*int currentRegency = tomLayer.getSynchronizer().getLCManager().getLastReg();
            if (currentRegency > 0) {
                logger.debug("Removing STOP retransmissions up to regency {}", currentRegency);
                tomLayer.getSynchronizer().removeSTOPretransmissions(currentRegency - 1);
            }*/

            //logger.debug("Getting state up to {}", consensusId);
            DefaultApplicationState appState = (DefaultApplicationState) dt.getRecoverer().getState(consensusId, true);
            if (appState == null) {
                logger.debug("Something went wrong while retrieving state up to {}", consensusId);
                return;
            }

            ApplicationState refreshedState = refreshState(point, appState);
            if (refreshedState != null) {
                logger.info("Updating state");
                //dt.update(refreshedState);
                dt.refreshState(refreshedState);

                //tomLayer.setLastExec(lastExec);
                //tomLayer.setInExec(inExec);

                /*Queue<ConsensusMessage> stoppedMsgs = execManager.getStoppedMsgs();
                for (ConsensusMessage stoppedMsg : stoppedMsgs) {
                    logger.debug(stoppedMsg.toString());
                    if (stoppedMsg.getNumber() > tomLayer.getLastExec())
                        execManager.addOutOfContextMessage(stoppedMsg); //will separate proposal messages from others
                }

                logger.debug("Clear Stopped");
                execManager.clearStopped();
                logger.info("Restarting execution manager from lastExec {} and inExec {}", tomLayer.getLastExec(),
                        tomLayer.getInExec());
                execManager.restart();

                logger.debug("Processing out of context messages");
                tomLayer.processOutOfContext(); //will going to process proposal messages and others in correct consensus execution
                logger.debug("Finished processing out of context messages");*/
            }
            else
                logger.debug("State renewal ignored. Something went wrong while renewing the state");

            if (refreshedState != null)
                logger.debug("State renewed");

        } finally {
            dt.canDeliver();//signal deliverThread that state has been installed
            dt.deliverUnlock();

            setRefreshTimer();
        }

    }

    private DefaultApplicationState refreshState(VerifiableShare point, DefaultApplicationState appState) {
        BigInteger y = point.getShare().getShare();
        Commitments refreshCommitments = point.getCommitments();
        BigInteger field = distributedPolynomial.getField();
        long numShares = 0;
        byte[] renewedSnapshot = null;
        if (appState.hasState()) {
            ConfidentialSnapshot snapshot = ConfidentialSnapshot.deserialize(appState.getState());
            if (snapshot == null)
                return null;
            if (snapshot.getShares() != null && snapshot.getShares().length > 0) {
                ConfidentialData[] secretData = snapshot.getShares();
                for (ConfidentialData oldShare : secretData) {
                    VerifiableShare vs = oldShare.getShare();
                    vs.getShare().setShare(y.add(vs.getShare().getShare()).mod(field));
                    Commitments commitments = commitmentScheme.sumCommitments(vs.getCommitments(),
                            refreshCommitments);
                    vs.setCommitments(commitments);
                    numShares++;
                    if (oldShare.getPublicShares() != null)
                        for (VerifiableShare publicShare : oldShare.getPublicShares()) {
                            publicShare.getShare().setShare(y.add(publicShare.getShare().getShare()).mod(field));
                            commitments = commitmentScheme.sumCommitments(publicShare.getCommitments(),
                                    refreshCommitments);
                            publicShare.setCommitments(commitments);
                            numShares++;
                        }
                }

                renewedSnapshot = new ConfidentialSnapshot(snapshot.getPlainData(), secretData).serialize();
            }
        }

        CommandsInfo[] oldLogs = appState.getMessageBatches();
        CommandsInfo[] renewedLogs = new CommandsInfo[oldLogs.length];

        for (int i = 0; i < oldLogs.length; i++) {
            CommandsInfo oldLog = oldLogs[i];
            byte[][] commands = new byte[oldLog.commands.length][];
            for (int j = 0; j < oldLog.commands.length; j++) {
                Request request = Request.deserialize(oldLog.commands[j]);
                if (request == null || request.getShares() == null || request.getShares().length == 0)
                    commands[j] = oldLog.commands[j];
                else {
                    ConfidentialData[] secretData = request.getShares();
                    for (ConfidentialData oldShare : secretData) {
                        VerifiableShare vs = oldShare.getShare();
                        vs.getShare().setShare(y.add(vs.getShare().getShare()).mod(field));
                        Commitments commitments = commitmentScheme.sumCommitments(vs.getCommitments(),
                                refreshCommitments);
                        vs.setCommitments(commitments);
                        numShares++;
                        if (oldShare.getPublicShares() != null)
                            for (VerifiableShare publicShare : oldShare.getPublicShares()) {
                                publicShare.getShare().setShare(y.add(publicShare.getShare().getShare()).mod(field));
                                commitments = commitmentScheme.sumCommitments(publicShare.getCommitments(),
                                        refreshCommitments);
                                publicShare.setCommitments(commitments);
                                numShares++;
                            }
                    }
                    commands[j] = new Request(request.getType(), request.getPlainData(), secretData).serialize();
                }
            }
            renewedLogs[i] = new CommandsInfo(commands, oldLog.msgCtx);
        }

        logger.info("Renewed {} shares", numShares);

        return new DefaultApplicationState(
                renewedLogs,
                appState.getLastCheckpointCID(),
                appState.getLastCID(),
                renewedSnapshot == null ? appState.getState() : renewedSnapshot,
                renewedSnapshot == null ? appState.getStateHash() : TOMUtil.computeHash(renewedSnapshot),
                SVController.getStaticConf().getProcessId()
        );
    }

    private void setRefreshTimer() {
        refreshTriggerTask = new TimerTask() {
            @Override
            public void run() {
                renewalStartTime = System.nanoTime();
                int id = sequenceNumber.getAndIncrement();
                PolynomialContext context = new PolynomialContext(
                        id,
                        SVController.getCurrentViewF(),
                        BigInteger.ZERO,
                        BigInteger.ZERO,
                        SVController.getCurrentViewAcceptors(),
                        tomLayer.execManager.getCurrentLeader(),
                        PolynomialCreationReason.RESHARING
                );
                logger.debug("Starting creation of new polynomial with id {} for resharing", id);
                distributedPolynomial.createNewPolynomial(context);
            }
        };

        refreshTimer.schedule(refreshTriggerTask, REFRESH_PERIOD);
    }

    private void sendRecoveryState(DefaultSMMessage recoveryMessage, VerifiableShare recoveryPoint) {
        logger.debug("Creating recovery state up to CID {} for {}", recoveryMessage.getCID(),
                recoveryMessage.getSender());
        DefaultApplicationState appState = (DefaultApplicationState)dt.getRecoverer().getState(recoveryMessage.getCID(), true);
        if (appState == null || appState.getMessageBatches() == null) {
            logger.debug("Ignoring this state transfer request because app state is null");
            return;
        }

        logger.debug("Sending sequence number {} with the state", sequenceNumber.get());
        RecoveryStateServerSMMessage response = new RecoveryStateServerSMMessage(
                SVController.getStaticConf().getProcessId(),
                appState.getLastCID(),
                TOMUtil.SM_REPLY,
                SVController.getCurrentView(),
                tomLayer.getSynchronizer().getLCManager().getLastReg(),
                recoveryMessage.getLeader(),
                sequenceNumber.get()
        );

        try {
            logger.debug("Starting recovery state sender thread");
            new RecoveryStateSender(
                    recoveryMessage.getServerPort(),
                    SVController.getCurrentView().getAddress(recoveryMessage.getSender()).getAddress().getHostAddress(),
                    appState,
                    recoveryPoint,
                    distributedPolynomial.getField(),
                    SVController,
                    recoveryMessage.getStateSenderReplica() == SVController.getStaticConf().getProcessId()
            ).start();
        } catch (Exception e) {
            e.printStackTrace();
        }

        logger.info("Sending recovery state sender server info to {}", recoveryMessage.getSender());
        tomLayer.getCommunication().send(new int[]{recoveryMessage.getSender()}, response);
        logger.info("Recovery state sender server info sent");
    }
}
