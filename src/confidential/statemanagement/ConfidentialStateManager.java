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
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

public class ConfidentialStateManager extends StateManager implements PolynomialCreationListener, VerificationCompleted {
    private static final long REFRESH_PERIOD = 120000;
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
    private BigInteger shareholder;
    private Set<Integer> sequenceNumbers;
    private Timer refreshTimer;
    private TimerTask refreshTriggerTask;
    private StateVerifierHandlerThread stateVerifierHandlerThread;

    public ConfidentialStateManager() {
        lockTimer = new ReentrantLock();
        sequenceNumber = new AtomicInteger();
        onGoingRecoveryRequests = new HashMap<>();
        sequenceNumbers = new HashSet<>();
        refreshTimer = new Timer("Refresh Timer");
    }

    public void setDistributedPolynomial(DistributedPolynomial distributedPolynomial) {
        this.shareholder = distributedPolynomial.getShareholderId();
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RECOVERY);
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RESHARING);
        this.distributedPolynomial = distributedPolynomial;
        //setRefreshTimer();
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

    @Override
    protected void requestState() {
        logger.debug("requestState");
        if (tomLayer.requestsTimer != null)
            tomLayer.requestsTimer.clearAll();

        DefaultSMMessage recoverySMMessage = new DefaultSMMessage(
                SVController.getStaticConf().getProcessId(),
                waitingCID,
                TOMUtil.SM_REQUEST,
                null,
                SVController.getCurrentView(),
                -1,
                tomLayer.execManager.getCurrentLeader()
        );


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
                        -1
                );
                triggerTimeout(message);
            }
        };

        stateVerifierHandlerThread = new StateVerifierHandlerThread(this, SVController.getCurrentViewF(),
                commitmentScheme);
        stateVerifierHandlerThread.start();

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
        }
    }

    @Override
    public void SMReplyDeliver(SMMessage msg, boolean isBFT) {
        try {
            lockTimer.lock();
            RecoverySMMessage recoverySMMessage = (RecoverySMMessage)msg;
            logger.info("{} sent me state up to cid {}", msg.getSender(), msg.getCID());
            logger.debug("waitingCID: {}" , waitingCID);
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

            logger.debug("Submitting state from {} to verification", msg.getSender());
            stateVerifierHandlerThread.addStateForVerification(recoverySMMessage);
        } finally {
            lockTimer.unlock();
        }
    }

    @Override
    public void onVerificationCompleted(boolean valid, RecoverySMMessage msg) {
        try {
            lockTimer.lock();
            if (!valid) {
                logger.info("{} sent me invalid state", msg.getSender());
                return;
            }

            logger.info("{} sent me valid state", msg.getSender());

            int currentRegency = -1;
            int currentLeader = -1;
            View currentView = null;

            if (!appStateOnly) {
                if (enoughRegencies(msg.getRegency())) {
                    currentRegency = msg.getRegency();
                }
                if (enoughLeaders(msg.getLeader())) {
                    currentLeader = msg.getLeader();
                }
                if (enoughViews(msg.getView())) {
                    currentView = msg.getView();
                }
            } else {
                currentLeader = tomLayer.execManager.getCurrentLeader();
                currentRegency = tomLayer.getSynchronizer().getLCManager().getLastReg();
                currentView = SVController.getCurrentView();
            }

            sequenceNumbers.add(msg.getSequenceNumber());
            senderStates.put(msg.getSender(), msg.getState());

            if (!enoughReplies())
                return;

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

            stateVerifierHandlerThread.interrupt();

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
            if (sequenceNumbers.size() > 1) {
                logger.error("Sequence numbers are different");
                reset();
                requestState();
                return;
            }

            sequenceNumber.set(msg.getSequenceNumber());

            state = recoverState(senderStates.values());

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

            tomLayer.processOutOfContext();

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
        }
    }

    @Override
    public void onPolynomialCreation(PolynomialContext context, VerifiableShare point, int consensusId) {
        logger.debug("Received my point for {} with id {}", context.getReason(), context.getId());
        if (sequenceNumber.get() <= context.getId())
            sequenceNumber.set(context.getId() + 1);
        if (SVController.getStaticConf().isStateTransferEnabled() && dt.getRecoverer() != null
                && context.getReason() == PolynomialCreationReason.RECOVERY) {
            if (onGoingRecoveryRequests.containsKey(context.getId()))
                sendRecoveryState(onGoingRecoveryRequests.remove(context.getId()), point);
            else
                logger.debug("There is no recovery request for id {}", context.getId());
        } else if (PolynomialCreationReason.RESHARING == context.getReason()) {
            refreshTriggerTask.cancel();
            refreshState(point, consensusId);
        }
    }

    private void refreshState(VerifiableShare point, int consensusId) {
        try {
            logger.debug("Renewing my state");


            waitingCID = consensusId;// will make DeliveryThread to stop waiting for state

            dt.deliverLock();

            int currentRegency = tomLayer.getSynchronizer().getLCManager().getLastReg();
            if (currentRegency > 0) {
                logger.debug("Removing STOP retransmissions up to regency {}", currentRegency);
                tomLayer.getSynchronizer().removeSTOPretransmissions(currentRegency - 1);
            }

            logger.debug("Getting state up to {}", consensusId);
            DefaultApplicationState appState = (DefaultApplicationState) dt.getRecoverer().getState(consensusId, true);
            if (appState == null) {
                logger.debug("Something went wrong while retrieving state up to {}", consensusId);
                return;
            }

            ApplicationState refreshedState = refreshState(point, appState);
            if (refreshedState != null)
                dt.update(refreshedState);
            else
                logger.debug("State renewal ignored. Something went wrong while renewing the state");

            if (refreshedState != null)
                logger.debug("State renewed");

        } finally {
            waitingCID = -1;
            dt.canDeliver();//signal deliverThread that state has been installed
            dt.deliverUnlock();
            setRefreshTimer();
        }

    }

    private DefaultApplicationState refreshState(VerifiableShare point, DefaultApplicationState appState) {
        BigInteger shareholder = point.getShare().getShareholder();
        BigInteger y = point.getShare().getShare();
        Commitments refreshCommitments = point.getCommitments();
        BigInteger field = distributedPolynomial.getField();
        byte[] renewedSnapshot = null;
        if (appState.hasState()) {
            ConfidentialSnapshot snapshot = ConfidentialSnapshot.deserialize(appState.getState());
            if (snapshot == null)
                return null;
            if (snapshot.getShares() != null && snapshot.getShares().length > 0) {
                VerifiableShare[] oldShares = snapshot.getShares();
                VerifiableShare[] renewedShares = new VerifiableShare[oldShares.length];
                for (int i = 0; i < oldShares.length; i++) {
                    VerifiableShare oldShare = oldShares[i];
                    Share share = new Share(shareholder, y.add(oldShare.getShare().getShare()).mod(field));
                    Commitments commitments = commitmentScheme.sumCommitments(oldShare.getCommitments(),
                            refreshCommitments);
                    renewedShares[i] = new VerifiableShare(share, commitments, oldShare.getSharedData());
                }

                renewedSnapshot = new ConfidentialSnapshot(snapshot.getPlainData(), renewedShares).serialize();
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
                    VerifiableShare[] oldShares = request.getShares();
                    VerifiableShare[] renewedShares = new VerifiableShare[oldShares.length];
                    for (int k = 0; k < oldShares.length; k++) {
                        VerifiableShare oldShare = oldShares[k];
                        Share share = new Share(shareholder, y.add(oldShare.getShare().getShare()).mod(field));
                        Commitments commitments = commitmentScheme.sumCommitments(oldShare.getCommitments(),
                                refreshCommitments);
                        renewedShares[k] = new VerifiableShare(share, commitments, oldShare.getSharedData());
                    }
                    commands[j] = new Request(request.getType(), request.getPlainData(), renewedShares).serialize();
                }
            }
            renewedLogs[i] = new CommandsInfo(commands, oldLog.msgCtx);
        }

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



    private ApplicationState recoverState(Collection<ApplicationState> recoveryStates) {
        if (recoveryStates.size() <= SVController.getCurrentViewF()) {
            logger.debug("Not enough recovery states");
            return null;
        }

        int counter = 1;

        //Recovering log and checking if all the members used same recovery polynomial
        Iterator<ApplicationState> iterator = recoveryStates.iterator();
        RecoveryApplicationState firstState = (RecoveryApplicationState) iterator.next();
        CommandsInfo[][] recoveryLog = new CommandsInfo[firstState.getMessageBatches().length][recoveryStates.size()];
        CommandsInfo[] log = firstState.getMessageBatches();
        for (int i = 0; i < log.length; i++) {
            recoveryLog[i][0] = log[i];
        }

        Commitments polynomialCommitments = firstState.getTransferPolynomialCommitments();
        while (iterator.hasNext()){
            RecoveryApplicationState recoveryState = (RecoveryApplicationState)iterator.next();
            if (!polynomialCommitments.equals(recoveryState.getTransferPolynomialCommitments())) {
                logger.debug("Transfer polynomial commitments are different");
                return null;
            }
            log = recoveryState.getMessageBatches();
            for (int i = 0; i < log.length; i++) {
                recoveryLog[i][counter] = log[i];
            }
            counter++;
        }

        CommandsInfo[] recoveredLog = new CommandsInfo[recoveryLog.length];
        for (int i = 0; i < recoveredLog.length; i++) {
            recoveredLog[i] = recoverCommandsInfo(recoveryLog[i]);
        }

        //Recovering snapshot
        iterator = recoveryStates.iterator();
        iterator.next();
        ConfidentialSnapshot firstSnapshot = firstState.hasState() ?
                ConfidentialSnapshot.deserialize(firstState.getSerializedState()) : null;

        byte[] snapshotPlainData = firstSnapshot == null ? null : firstSnapshot.getPlainData();
        VerifiableShare[] shares = firstSnapshot != null && firstSnapshot.getShares() != null ?
                new VerifiableShare[firstSnapshot.getShares().length] : null;


        if (shares != null) {
            Share[][] recoveryShares = new Share[shares.length][recoveryStates.size()];
            for (int i = 0; i < firstSnapshot.getShares().length; i++) {
                recoveryShares[i][0] = firstSnapshot.getShares()[i].getShare();
            }
            counter = 1;
            while (iterator.hasNext()) {
                RecoveryApplicationState recoveryState = (RecoveryApplicationState) iterator.next();
                ConfidentialSnapshot recoverySnapshot = ConfidentialSnapshot.deserialize(recoveryState.getSerializedState());
                if (recoverySnapshot == null)
                    return null;
                for (int i = 0; i < recoverySnapshot.getShares().length; i++) {
                    recoveryShares[i][counter] = recoverySnapshot.getShares()[i].getShare();
                }
                counter++;
            }

            for (int i = 0; i < shares.length; i++) {
                Share share = new Share(shareholder, interpolationStrategy.interpolateAt(shareholder, recoveryShares[i]));
                VerifiableShare vs = firstSnapshot.getShares()[i];
                shares[i] = new VerifiableShare(share, vs.getCommitments(), vs.getSharedData());
            }
        }

        ConfidentialSnapshot recoveredState = firstSnapshot == null ? null
                : (shares == null ? new ConfidentialSnapshot(snapshotPlainData)
                : new ConfidentialSnapshot(snapshotPlainData, shares));
        byte[] serializedState = recoveredState == null ? null : recoveredState.serialize();

        return new DefaultApplicationState(recoveredLog, firstState.getLastCheckpointCID(),
                firstState.getLastCID(), serializedState, serializedState == null ? null : TOMUtil.computeHash(serializedState),
                SVController.getStaticConf().getProcessId());

    }

    private CommandsInfo recoverCommandsInfo(CommandsInfo[] commandsInfos) {
        int numCommands = commandsInfos[0].commands.length;
        int t = commandsInfos.length;
        byte[][] recoveredCommands = new byte[numCommands][];

        commands: for (int i = 0; i < numCommands; i++) {
            byte[][] commandToRecover = new byte[t][];
            for (int j = 0; j < t; j++) {
                commandToRecover[j] = commandsInfos[j].commands[i];
            }

            Request request = null;
            Share[][] shares = null;

            for (int j = 0; j < t; j++) {
                request = Request.deserialize(commandToRecover[j]);
                if (request == null || request.getShares() == null || request.getShares().length == 0) {
                    recoveredCommands[i] = commandToRecover[j];
                    continue commands;
                }
                if (shares == null)
                    shares = new Share[request.getShares().length][t];
                for (int k = 0; k < request.getShares().length; k++) {
                    shares[k][j] = request.getShares()[k].getShare();
                }
            }
            VerifiableShare[] verifiableShares = new VerifiableShare[request.getShares().length];
            for (int j = 0; j < verifiableShares.length; j++) {
                Share share = new Share(shareholder, interpolationStrategy.interpolateAt(shareholder, shares[j]));
                VerifiableShare vs = request.getShares()[j];
                verifiableShares[j] = new VerifiableShare(share, vs.getCommitments(), vs.getSharedData());
            }
            recoveredCommands[i] = new Request(request.getType(), request.getPlainData(), verifiableShares).serialize();
        }

        return new CommandsInfo(recoveredCommands, commandsInfos[0].msgCtx);
    }

    private void sendRecoveryState(SMMessage recoveryMessage, VerifiableShare recoveryPoint) {
        logger.debug("Creating recovery state up to CID {} for {}", recoveryMessage.getCID(),
                recoveryMessage.getSender());
        DefaultApplicationState appState = (DefaultApplicationState)dt.getRecoverer().getState(recoveryMessage.getCID(), true);
        if (appState == null || appState.getMessageBatches() == null) {
            logger.debug("Ignoring this state transfer request because app state is null");
            return;
        }

        ConfidentialSnapshot recoverySnapshot = null;
        if (appState.hasState())
            recoverySnapshot = createRecoverySnapshot(ConfidentialSnapshot.deserialize(appState.getSerializedState()),
                    recoveryPoint);

        CommandsInfo[] recoveryLog = createRecoveryLog(appState.getMessageBatches(), recoveryPoint);
        byte[] serializedState = recoverySnapshot != null ? recoverySnapshot.serialize() : null;

        ApplicationState recoveryState = new RecoveryApplicationState(
                recoveryLog,
                appState.getLastCheckpointCID(),
                appState.getLastCID(),
                serializedState,
                TOMUtil.computeHash(serializedState),
                SVController.getStaticConf().getProcessId(),
                recoveryPoint.getCommitments()
        );
        logger.debug("Sending sequence number {} with the state", sequenceNumber.get());
        RecoverySMMessage response = new RecoverySMMessage(
                SVController.getStaticConf().getProcessId(),
                appState.getLastCID(),
                TOMUtil.SM_REPLY,
                recoveryState,
                SVController.getCurrentView(),
                tomLayer.getSynchronizer().getLCManager().getLastReg(),
                recoveryMessage.getLeader(),
                sequenceNumber.get()
        );

        logger.info("Sending recovery state up to {} to {}", recoveryState.getLastCID(),
                recoveryMessage.getSender());
        tomLayer.getCommunication().send(new int[] {recoveryMessage.getSender()}, response);
        logger.info("Recovery state sent");
    }

    private CommandsInfo[] createRecoveryLog(CommandsInfo[] log, VerifiableShare recoveryPoint) {
        CommandsInfo[] recoveryLog = new CommandsInfo[log.length];

        BigInteger shareholder = recoveryPoint.getShare().getShareholder();
        BigInteger y = recoveryPoint.getShare().getShare();
        for (int i = 0; i < log.length; i++) {
            byte[][] commands = log[i].commands;
            byte[][] recoveryCommands = new byte[commands.length][];
            for (int j = 0; j < commands.length; j++) {
                Request request = Request.deserialize(commands[j]);
                if (request == null) {
                    logger.warn("Something went wrong while deserializing request");
                    recoveryCommands[j] = commands[j];
                    continue;
                }
                VerifiableShare[] shares = request.getShares();
                if (shares == null) {
                    recoveryCommands[j] = commands[j];
                } else {
                    VerifiableShare[] recoveryShares = new VerifiableShare[shares.length];

                    for (int k = 0; k < shares.length; k++) {
                        VerifiableShare shareToRecover = shares[k];
                        BigInteger share = y.add(shareToRecover.getShare().getShare()).mod(distributedPolynomial.getField());
                        recoveryShares[k] = new VerifiableShare(
                                new Share(shareholder, share),
                                shareToRecover.getCommitments(),
                                shareToRecover.getSharedData()
                        );
                    }

                    recoveryCommands[j] = new Request(request.getType(), request.getPlainData(), recoveryShares).serialize();
                }
            }
            recoveryLog[i] = new CommandsInfo(recoveryCommands, log[i].msgCtx);
        }

        return recoveryLog;
    }

    private ConfidentialSnapshot createRecoverySnapshot(ConfidentialSnapshot snapshot, VerifiableShare recoveryPoint) {
        if (snapshot == null)
            return null;
        if (snapshot.getShares() == null)
            return snapshot;
        byte[] plainData = snapshot.getPlainData();
        VerifiableShare[] shares = snapshot.getShares();
        int numShares = shares.length;
        VerifiableShare[] recoveryShares = new VerifiableShare[numShares];
        BigInteger shareholder = recoveryPoint.getShare().getShareholder();
        BigInteger y = recoveryPoint.getShare().getShare();
        VerifiableShare shareToRecover;

        for (int i = 0; i < numShares; i++) {
            shareToRecover = shares[i];
            BigInteger share = y.add(shareToRecover.getShare().getShare()).mod(distributedPolynomial.getField());
            recoveryShares[i] = new VerifiableShare(
                    new Share(shareholder, share),
                    shareToRecover.getCommitments(),
                    shareToRecover.getSharedData()
            );
        }

        return new ConfidentialSnapshot(plainData, recoveryShares);
    }
}
