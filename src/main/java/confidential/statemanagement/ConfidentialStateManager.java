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
import confidential.statemanagement.privatestate.receiver.COBRAStateCombiner;
import confidential.statemanagement.privatestate.receiver.StateReceivedListener;
import confidential.statemanagement.privatestate.sender.COBRAStateSeparator;
import confidential.statemanagement.privatestate.sender.StateSeparationListener;
import confidential.statemanagement.recovery.RecoveryBlindedStateHandler;
import confidential.statemanagement.recovery.RecoveryBlindedStateSender;
import confidential.statemanagement.resharing.ResharingBlindedStateHandler;
import confidential.statemanagement.resharing.ResharingBlindedStateSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

public class ConfidentialStateManager extends StateManager implements ReconstructionCompleted,
        RecoveryPolynomialListener, ResharingPolynomialListener {
    private final long RENEWAL_PERIOD;
    private final int SERVER_RESHARING_STATE_LISTENING_PORT;
    private final int SERVER_RECOVERY_STATE_LISTENING_PORT;
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
    private final PolynomialStorage resharingNewGroupPoints;

    public ConfidentialStateManager() {
        lockTimer = new ReentrantLock();
        onGoingRecoveryRequests = new ConcurrentHashMap<>();
        sequenceNumbers = new HashMap<>();
        refreshTimer = new Timer("Refresh Timer");
        usedReplicas = new HashSet<>();
        RENEWAL_PERIOD = Configuration.getInstance().getRenewalPeriod();
        SERVER_RECOVERY_STATE_LISTENING_PORT = Configuration.getInstance().getRecoveryPort();
        SERVER_RESHARING_STATE_LISTENING_PORT = SERVER_RECOVERY_STATE_LISTENING_PORT * 2;
        resharingNewGroupPoints = new PolynomialStorage();
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
                SERVER_RECOVERY_STATE_LISTENING_PORT
        );

        logger.info("Replica {} will send full state", stateSenderReplica);
        int f = SVController.getCurrentViewF();
        int quorum = SVController.getCurrentViewN() - f;
        logger.info("Starting recovery state handler");
        StateReceivedListener stateReceivedListener = (commonState, shares)
                -> new COBRAStateCombiner(SVController.getStaticConf().getProcessId(),
                commonState, shares, this).start();
        new RecoveryBlindedStateHandler(
                SVController,
                SERVER_RECOVERY_STATE_LISTENING_PORT,
                f,
                quorum,
                stateSenderReplica,
                confidentialityScheme,
                stateReceivedListener
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

            DefaultApplicationState appState = (DefaultApplicationState) dt.getRecoverer().getState(msg.getCID(), true);
            if (appState == null || appState.getMessageBatches() == null) {
                logger.warn("Ignoring this state transfer request because app state is null");
                return;
            }

            DefaultSMMessage defaultSMMessage = (DefaultSMMessage) msg;

            StateSeparationListener listener = (commonState, shares, commitments)
                    -> triggerRecoveryStateTransfer(msg, defaultSMMessage.getStateSenderReplica(),
                    defaultSMMessage.getServerPort(), commonState, shares, commitments);

            new COBRAStateSeparator(
                    appState,
                    listener
            ).start();
        } else if (msg instanceof PolynomialRecovery) {
            logger.info("Received polynomial recovery request from {}", msg.getSender());
            PolynomialRecovery request = (PolynomialRecovery)msg;
            VerifiableShare[] points = resharingNewGroupPoints.getPoints(request.getId());
            if (points == null) {
                logger.info("I do not have points for new group");
            } else {
                LinkedList<Share> shares = new LinkedList<>();
                LinkedList<Commitment> commitments = new LinkedList<>();

                int[] polynomialInitialIds = request.getPolynomialInitialIds();
                int[] nPolynomialsPerId = request.getNPolynomialsPerId();

                for (int i = 0; i < polynomialInitialIds.length; i++) {
                    int initialId = polynomialInitialIds[i];
                    int quantity = nPolynomialsPerId[i];
                    for (int j = initialId; j < initialId + quantity; j++) {
                        VerifiableShare point = points[j];
                        shares.add(point.getShare());
                        commitments.add(point.getCommitments());
                    }
                }

                triggerRecoveryStateTransfer(msg, request.getStateSenderReplica(), request.getServerPort(),
                        new byte[0], shares, commitments);
            }
        } else
            logger.warn("Received unknown SM message type from {}", msg.getSender());
    }

    private void triggerRecoveryStateTransfer(SMMessage recoveryMessage, int fullStateSenderReplica, int serverPort,
                                              byte[] commonState, LinkedList<Share> shares,
                                              LinkedList<Commitment> commitments) {
        boolean iAmStateSender =
                fullStateSenderReplica == SVController.getStaticConf().getProcessId();
        recoveryStateSender = new RecoveryBlindedStateSender(
                SVController,
                commonState,
                shares,
                commitments,
                serverPort,
                confidentialityScheme,
                iAmStateSender,
                recoveryMessage.getSender()
        );
        recoveryStateSender.start();
        int id = distributedPolynomialManager.createRecoveryPolynomialsFor(
                recoveryMessage.getSender(),
                confidentialityScheme.getShareholder(recoveryMessage.getSender()),
                SVController.getCurrentViewF(),
                SVController.getCurrentViewAcceptors(),
                shares.size()
        );
        onGoingRecoveryRequests.put(id, recoveryMessage);
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
    public void onRecoveryPolynomialsFailure(RecoveryPolynomialContext context) {
        int counter = (int) Arrays.stream(context.getPoints()).filter(Objects::isNull).count();
        logger.warn("Received {} invalid polynomials for recovery", counter);


    }

    @Override
    public void onRecoveryPolynomialsCreation(RecoveryPolynomialContext context) {
        logger.debug("Received {} polynomials for recovery", context.getNPolynomials());

        if (onGoingRecoveryRequests.containsKey(context.getInitialId())) {
            SMMessage recoveryMessage = onGoingRecoveryRequests.remove(context.getInitialId());
            if (recoveryMessage instanceof DefaultSMMessage) {
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
            } else if (recoveryMessage instanceof PolynomialRecovery) {
                recoveryStateSender.setBlindingShares(context.getPoints());
                recoveryStateSender = null;
            }
        } else
            logger.debug("There is no recovery request for id {}", context.getInitialId());
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

        StateSeparationListener listener = (commonState, shares, commitments) -> {
            resharingStateSender = new ResharingBlindedStateSender(
                    SVController,
                    commonState,
                    shares,
                    commitments,
                    SERVER_RESHARING_STATE_LISTENING_PORT,
                    confidentialityScheme,
                    iAmStateSender,
                    newGroup
            );
            resharingStateSender.start();
            distributedPolynomialManager.createResharingPolynomials(
                    currentF,
                    currentGroup,
                    newF,
                    newGroup,
                    shares.size());
        };
        new COBRAStateSeparator(
                appState,
                listener
        ).start();
    }

    @Override
    public void onResharingPolynomialsFailure(ResharingPolynomialContext context) {
        int[] newMembers = context.getNewMembers();
        int processId = SVController.getStaticConf().getProcessId();
        if (!Utils.isIn(processId, newMembers)) {
            logger.warn("Received invalid polynomials for resharing but I am not in new view.");
            System.exit(0);
        }

        VerifiableShare[] pointsForNewGroup = context.getPointsForNewGroup();
        int counter = (int) Arrays.stream(pointsForNewGroup).filter(Objects::isNull).count();
        logger.warn("Received {} invalid polynomials for resharing", counter);

        int size = context.getInvalidPolynomialsContexts().size();
        int[] ids = new int[size];
        int[] nPolynomials = new int[size];
        int index = 0;
        for (Map.Entry<Integer, InvalidPolynomialContext> entry : context.getInvalidPolynomialsContexts().entrySet()) {
            ids[index] = entry.getKey();
            nPolynomials[index] = entry.getValue().getNInvalidPolynomials();
            index++;
        }
        logger.info("Invalid polynomial ids: {}", Arrays.toString(ids));
        logger.info("Number of invalid polynomials per id: {}", Arrays.toString(nPolynomials));
        int stateSenderReplica = getRandomReplica();
        int f = SVController.getCurrentViewF();
        int quorum = SVController.getCurrentViewN() - f;
        StateReceivedListener stateReceivedListener = (commonState, shares) -> {
            Iterator<VerifiableShare> it = shares.iterator();
            for (int i = 0; i < ids.length; i++) {
                pointsForNewGroup[ids[i]] = it.next();
            }

            isRefreshing = true;
            resharingStateSender.interrupt();
            resharingStateSender = null;
            resharingStateHandler.setRefreshShares(context.getPointsForNewGroup());
            resharingNewGroupPoints.putPoints(context.getMaxCID(), context.getPointsForNewGroup());
        };
        new RecoveryBlindedStateHandler(
                SVController,
                SERVER_RECOVERY_STATE_LISTENING_PORT,
                f,
                quorum,
                stateSenderReplica,
                confidentialityScheme,
                stateReceivedListener
        ).start();
        PolynomialRecovery request = new PolynomialRecovery(context.getMaxCID(),
                SVController.getStaticConf().getProcessId(), TOMUtil.SM_REQUEST, stateSenderReplica,
                SERVER_RECOVERY_STATE_LISTENING_PORT, ids, nPolynomials);
        logger.info("Sending polynomial recovery request to {}", Arrays.toString(context.getNewMembers()));
        tomLayer.getCommunication().send(context.getNewMembers(), request);
    }

    @Override
    public void onResharingPolynomialsCreation(ResharingPolynomialContext context) {
        logger.debug("Received {} polynomials for resharing", context.getNPolynomials());
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
            resharingNewGroupPoints.putPoints(context.getMaxCID(), context.getPointsForNewGroup());
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
        logger.info("Total renewal time: {} ms", totalTime);
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
        StateReceivedListener stateReceivedListener = (commonState, shares)
                -> new COBRAStateCombiner(SVController.getStaticConf().getProcessId(),
                commonState, shares, this).start();
        resharingStateHandler = new ResharingBlindedStateHandler(
                SVController,
                SERVER_RESHARING_STATE_LISTENING_PORT,
                f,
                reconfigurationParameters.getNewF(),
                quorum,
                stateSenderReplica,
                confidentialityScheme,
                stateReceivedListener
        );
        logger.info("Starting resharing state handler");
        resharingStateHandler.start();
        startResharing(consensusId, stateSenderReplica, f, group,
                reconfigurationParameters.getNewF(), group);
    }

    private ResharingBlindedStateHandler resharingStateHandler;

    private void setRefreshTimer() {
        if (Configuration.getInstance().isRenewalActive())
            throw new UnsupportedOperationException("Send reconfiguration request from admin client for the same threshold to use refresh.");
        StateReceivedListener stateReceivedListener = (commonState, shares)
                -> new COBRAStateCombiner(SVController.getStaticConf().getProcessId(),
                commonState, shares, this).start();
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
                        SERVER_RESHARING_STATE_LISTENING_PORT,
                        f,
                        f,
                        quorum,
                        leader,
                        confidentialityScheme,
                        stateReceivedListener
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
