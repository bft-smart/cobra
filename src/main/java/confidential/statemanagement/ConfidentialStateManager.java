package confidential.statemanagement;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.SMMessage;
import bftsmart.statemanagement.StateManager;
import bftsmart.tom.core.DeliveryThread;
import bftsmart.tom.core.TOMLayer;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import confidential.Configuration;
import confidential.Utils;
import confidential.polynomial.*;
import confidential.reconfiguration.ReconfigurationParameters;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.privatestate.sender.StateSeparationListener;
import confidential.statemanagement.recovery.RecoveryBlindedStateHandler;
import confidential.statemanagement.recovery.RecoveryBlindedStateSender;
import confidential.statemanagement.resharing.ResharingBlindedStateHandler;
import confidential.statemanagement.resharing.ResharingBlindedStateSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

public class ConfidentialStateManager extends StateManager implements ReconstructionCompleted,
        RecoveryPolynomialListener, ResharingPolynomialListener {
    private final long RENEWAL_PERIOD;
    private final int SERVER_STATE_LISTENING_PORT;
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private final static long INIT_TIMEOUT = 60 * 60 * 1000;
    private DistributedPolynomialManager distributedPolynomialManager;
    private ServerConfidentialityScheme confidentialityScheme;
    private Timer stateTimer;
    private long timeout = INIT_TIMEOUT;
    private final ReentrantLock lockTimer;
    private final Map<Integer, SMMessage> onGoingRecoveryRequests;
    private final HashMap<Integer, Integer> sequenceNumbers;
    private final Timer refreshTimer;
    private TimerTask refreshTriggerTask;
    private long recoveryStartTime;
    private long renewalStartTime;
    private final Set<Integer> usedReplicas;
    private boolean isRefreshing;
    private RecoveryBlindedStateSender recoveryStateSender;
    private ResharingBlindedStateSender resharingStateSender;
    private ReconfigurationParameters reconfigurationParameters;

    public ConfidentialStateManager() {
        lockTimer = new ReentrantLock();
        onGoingRecoveryRequests = new ConcurrentHashMap<>();
        sequenceNumbers = new HashMap<>();
        refreshTimer = new Timer("Refresh Timer");
        usedReplicas = new HashSet<>();
        RENEWAL_PERIOD = Configuration.getInstance().getRenewalPeriod();
        SERVER_STATE_LISTENING_PORT = Configuration.getInstance().getRecoveryPort();
    }

    public void setDistributedPolynomial(DistributedPolynomial distributedPolynomial) {
        this.distributedPolynomialManager = new DistributedPolynomialManager(distributedPolynomial,
                this, this);
        if (Configuration.getInstance().isRenewalActive()) {
            setRefreshTimer();
            logger.info("Renewal is active ({} s period)", RENEWAL_PERIOD / 1000);
        } else
            logger.info("Renewal is deactivated");
    }

    public void setConfidentialityScheme(ServerConfidentialityScheme confidentialityScheme) {
        this.confidentialityScheme = confidentialityScheme;
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
        int f = SVController.getCurrentViewF();
        int quorum = SVController.getCurrentViewN() - f;
        logger.info("Starting recovery state handler");
        new RecoveryBlindedStateHandler(
                SVController,
                SERVER_STATE_LISTENING_PORT,
                f,
                quorum,
                stateSenderReplica,
                confidentialityScheme,
                this
        ).start();

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
            if (!(SVController.getStaticConf().isStateTransferEnabled() && dt.getRecoverer() != null))
                return;

            DefaultApplicationState appState = (DefaultApplicationState)dt.getRecoverer().getState(msg.getCID(), true);
            if (appState == null || appState.getMessageBatches() == null) {
                logger.warn("Ignoring this state transfer request because app state is null");
                return;
            }

            DefaultSMMessage defaultSMMessage = (DefaultSMMessage) msg;
            boolean iAmStateSender =
                    defaultSMMessage.getStateSenderReplica() == SVController.getStaticConf().getProcessId();

            StateSeparationListener listener = nShares -> {
                int id = distributedPolynomialManager.createRecoveryPolynomialsFor(
                        msg.getSender(),
                        confidentialityScheme.getShareholder(msg.getSender()),
                        SVController.getCurrentViewF(),
                        SVController.getCurrentViewAcceptors(),
                        nShares
                );
                onGoingRecoveryRequests.put(id, msg);
            };
            recoveryStateSender = new RecoveryBlindedStateSender(
                    SVController,
                    appState,
                    defaultSMMessage.getServerPort(),
                    confidentialityScheme,
                    iAmStateSender,
                    listener,
                    msg.getSender()
            );
            recoveryStateSender.start();
        } else
            logger.warn("Received unknown SM message type from {}", msg.getSender());
    }

    @Override
    public void SMReplyDeliver(SMMessage msg, boolean isBFT) {
        try {
            lockTimer.lock();
            RecoveryStateServerSMMessage recoverySMMessage = (RecoveryStateServerSMMessage)msg;

            if (!SVController.getStaticConf().isStateTransferEnabled())
                return;

            sequenceNumbers.merge(recoverySMMessage.getSequenceNumber(), 1, Integer::sum);

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
            onReconstructionCompleted((DefaultApplicationState) state);
        } finally {
            lockTimer.unlock();
        }
    }

    @Override
    public void onRecoveryPolynomialsCreation(RecoveryPolynomialContext context) {
        logger.info("Received {} polynomials for recovery", context.getNPolynomials());

        if (onGoingRecoveryRequests.containsKey(context.getId())) {
            SMMessage recoveryMessage = onGoingRecoveryRequests.remove(context.getId());
            RecoveryStateServerSMMessage response;
            int processId = SVController.getStaticConf().getProcessId();
            View currentView = SVController.getCurrentView();
            int lastReg = tomLayer.getSynchronizer().getLCManager().getLastReg();
            int leader = tomLayer.execManager.getCurrentLeader();
            int sequenceNumber = distributedPolynomialManager.getSequenceNumber();
            response = new RecoveryStateServerSMMessage(
                    processId,
                    recoveryMessage.getCID(),
                    TOMUtil.SM_REPLY,
                    currentView,
                    lastReg,
                    leader,
                    sequenceNumber
            );
            tomLayer.getCommunication().send(new int[]{recoveryMessage.getSender()}, response);
            logger.info("Sent minimum recovery state to {}", recoveryMessage.getSender());
            recoveryStateSender.setBlindingShares(context.getPoints());
            recoveryStateSender = null;
        } else
            logger.warn("There is no recovery request for id {}", context.getId());
    }

    private void startResharing(int cid, int leader, int currentF, int[] currentGroup, int newF, int[] newGroup) {
        dt.pauseDecisionDelivery();
        logger.info("Getting state up to cid {} for resharing", cid);
        DefaultApplicationState appState = (DefaultApplicationState) dt.getRecoverer().getState(cid, true);
        if (appState == null) {
            logger.error("Something went wrong while retrieving state up to {} for resharing", cid);
            return;
        }
        dt.resumeDecisionDelivery();
        boolean iAmStateSender = leader == SVController.getStaticConf().getProcessId();
        StateSeparationListener separationListener = nShares -> distributedPolynomialManager.createResharingPolynomials(
                currentF,
                currentGroup,
                newF,
                newGroup,
                nShares
        );

        resharingStateSender = new ResharingBlindedStateSender(
                SVController,
                appState,
                SERVER_STATE_LISTENING_PORT,
                confidentialityScheme,
                iAmStateSender,
                separationListener,
                newGroup
        );
        resharingStateSender.start();
    }

    @Override
    public void onResharingPolynomialsCreation(ResharingPolynomialContext context) {
        logger.info("Received {} polynomials for resharing", context.getNPolynomials());
        if (refreshTriggerTask != null)
            refreshTriggerTask.cancel();
        isRefreshing = true;
        int[] oldMembers = context.getOldMembers();
        int[] newMembers = context.getNewMembers();
        logger.info("Old members: {}", Arrays.toString(oldMembers));
        logger.info("New members: {}", Arrays.toString(newMembers));
        int processId = SVController.getStaticConf().getProcessId();
        if (Utils.isIn(processId, oldMembers)) {
            resharingStateSender.setBlindingShares(context.getPointsForOldGroup());
        }
        if (Utils.isIn(processId, newMembers)) {
            resharingStateHandler.setRefreshShares(context.getPointsForNewGroup());
        }
    }

    /**
     * This method will be called after state is reconstructed, which means that this server already
     * have received f + 1 correct recovery states
     * @param recoveredState Recovered State
     */
    @Override
    public void onReconstructionCompleted(DefaultApplicationState recoveredState) {
        if (isRefreshing) {
            finishRefresh(recoveredState);
            return;
        }
        try {
            lockTimer.lock();
            if (recoveredState != null && state == null)
                state = recoveredState;
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
            int seqNumber = getCorrectValue(sequenceNumbers);

            if (currentRegency == -1 || currentLeader == -1 || currentView == null || seqNumber == -1 ||
                    state == null) {
                logger.info("Waiting for more states");
                return;
            }

            logger.info("More than f states confirmed");

            if (stateTimer != null) {
                stateTimer.cancel();
            }

            logger.info("Restoring state");
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

            distributedPolynomialManager.setSequenceNumber(seqNumber);

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


            if (appStateOnly) {
                appStateOnly = false;
                tomLayer.getSynchronizer().resumeLC();
            }
            long recoveryEndTime = System.nanoTime();
            double totalTime = (recoveryEndTime - recoveryStartTime) / 1_000_000.0;
            logger.info("Total recovery time: {} ms", totalTime);
        } finally {
            lockTimer.unlock();
        }
    }

    protected void finishRefresh(DefaultApplicationState renewedState) {
        dt.pauseDecisionDelivery();
        logger.info("Updating state");
        dt.refreshState(renewedState);
        logger.debug("State renewed");

        long endTime = System.nanoTime();
        double totalTime = (endTime - renewalStartTime) / 1_000_000.0;
        logger.info("Total renewal time: {}", totalTime);
        dt.resumeDecisionDelivery();
        isRefreshing = false;
        resharingStateSender = null;
        if (Configuration.getInstance().isRenewalActive())
            setRefreshTimer();
    }

    public ReconfigurationParameters getReconfigurationParameters() {
        return reconfigurationParameters;
    }

    public void setReconfigurationParameters(int newF, Set<Integer> joiningServers, Set<Integer> leavingServers) {
        int currentF = SVController.getCurrentViewF();
        int[] currentGroup = SVController.getCurrentViewAcceptors();

        Set<Integer> tempServers = new HashSet<>(currentGroup.length + joiningServers.size());
        for (int currentServer : currentGroup) {
            tempServers.add(currentServer);
        }
        tempServers.addAll(joiningServers);
        tempServers.removeAll(leavingServers);

        int[] newGroup = new int[tempServers.size()];
        int iTemp = 0;
        for (Integer tempServer : tempServers) {
            newGroup[iTemp++] = tempServer;
        }

        reconfigurationParameters = new ReconfigurationParameters(
                currentF,
                currentGroup,
                newF,
                newGroup
        );
    }

    public void executeReconfiguration(int consensusId) {
        if (reconfigurationParameters.getNewF() == -1) {
            return;
        }
        int[] group = SVController.getCurrentViewAcceptors();
        int stateSenderReplica = group[consensusId % group.length];
        logger.info("Replica {} will send full reshared state", stateSenderReplica);
        int f = reconfigurationParameters.getOldF();
        int quorum = 2 * reconfigurationParameters.getOldF() + 1;
        resharingStateHandler = new ResharingBlindedStateHandler(
                SVController,
                SERVER_STATE_LISTENING_PORT,
                f,
                reconfigurationParameters.getNewF(),
                quorum,
                stateSenderReplica,
                confidentialityScheme,
                this
        );
        logger.info("Starting resharing state handler");
        resharingStateHandler.start();
        startResharing(consensusId, stateSenderReplica, f, group,
                reconfigurationParameters.getNewF(), group);
    }

    private ResharingBlindedStateHandler resharingStateHandler;

    private void setRefreshTimer() {
        ReconstructionCompleted reconstructionCompletedListener = this;
        refreshTriggerTask = new TimerTask() {
            @Override
            public void run() {
                renewalStartTime = System.nanoTime();
                int f = SVController.getCurrentViewF();
                int[] currentGroup = SVController.getCurrentViewAcceptors();
                int quorum = SVController.getCurrentViewN() - f;
                int leader = tomLayer.execManager.getCurrentLeader();
                resharingStateHandler = new ResharingBlindedStateHandler(
                        SVController,
                        SERVER_STATE_LISTENING_PORT,
                        f,
                        f,
                        quorum,
                        leader,
                        confidentialityScheme,
                        reconstructionCompletedListener
                );
                resharingStateHandler.start();
                int cid = 13;//TODO decide the correct cid
                startResharing(cid, leader, f, currentGroup, f, currentGroup);
            }
        };

        refreshTimer.schedule(refreshTriggerTask, RENEWAL_PERIOD);
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
}
