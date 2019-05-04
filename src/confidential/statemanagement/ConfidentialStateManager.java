package confidential.statemanagement;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.SMMessage;
import bftsmart.statemanagement.StateManager;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import confidential.polynomial.DistributedPolynomial;
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

public class ConfidentialStateManager extends StateManager implements PolynomialCreationListener {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private final static long INIT_TIMEOUT = 40000;
    private DistributedPolynomial distributedPolynomial;
    private CommitmentScheme commitmentScheme;
    private InterpolationStrategy interpolationStrategy;
    private Timer stateTimer;
    private long timeout = INIT_TIMEOUT;
    private ReentrantLock lockTimer;
    private AtomicInteger sequenceNumber;
    private Map<Integer, RecoverySMMessage> onGoingRecoveryRequests;
    private Map<Integer, VerifiableShare> recoveryPoints;
    private BigInteger shareholder;


    public ConfidentialStateManager() {
        lockTimer = new ReentrantLock();
        sequenceNumber = new AtomicInteger();
        onGoingRecoveryRequests = new HashMap<>();
        recoveryPoints = new HashMap<>();
    }

    public void setDistributedPolynomial(DistributedPolynomial distributedPolynomial) {
        this.shareholder = distributedPolynomial.getShareholderId();
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RECOVERY);
        this.distributedPolynomial = distributedPolynomial;
    }

    public void setInterpolationStrategy(InterpolationStrategy interpolationStrategy) {
        this.interpolationStrategy = interpolationStrategy;
    }

    public void setCommitmentScheme(CommitmentScheme commitmentScheme) {
        this.commitmentScheme = commitmentScheme;
    }

    @Override
    protected void requestState() {
        logger.debug("requestState");
        if (tomLayer.requestsTimer != null)
            tomLayer.requestsTimer.clearAll();
        int id = SVController.getStaticConf().getProcessId();
        distributedPolynomial.createNewPolynomial(
                id,
                SVController.getCurrentViewF(),
                tomLayer.execManager.getCurrentLeader(),
                SVController.getCurrentView().getId(),
                SVController.getCurrentViewOtherAcceptors(),
                BigInteger.valueOf(SVController.getStaticConf().getProcessId() + 1),
                BigInteger.ZERO,
                PolynomialCreationReason.RECOVERY
        );

        RecoverySMMessage recoverySMMessage = new RecoverySMMessage(
                SVController.getStaticConf().getProcessId(),
                waitingCID,
                TOMUtil.SM_REQUEST,
                null,
                SVController.getCurrentView(),
                -1,
                tomLayer.execManager.getCurrentLeader(),
                id
        );

        logger.info("Sending request for state up to CID {} to {}", waitingCID,
                Arrays.toString(SVController.getCurrentViewOtherAcceptors()));
        tomLayer.getCommunication().send(SVController.getCurrentViewOtherAcceptors(), recoverySMMessage);

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
        if (msg instanceof RecoverySMMessage) {
            RecoverySMMessage recoverySMMessage = (RecoverySMMessage)msg;
            logger.debug("Received recovery request from {} with id {}", recoverySMMessage.getSender(),
                    recoverySMMessage.getId());
            if (SVController.getStaticConf().isStateTransferEnabled() && dt.getRecoverer() != null) {
                if (recoveryPoints.containsKey(recoverySMMessage.getId()))
                    sendRecoveryState(recoverySMMessage, recoveryPoints.remove(recoverySMMessage.getId()));
                else
                    onGoingRecoveryRequests.put(recoverySMMessage.getId(), recoverySMMessage);
            }
        }
    }

    @Override
    public void onPolynomialCreation(PolynomialCreationReason reason, int id, VerifiableShare point) {
        logger.debug("Received my point to do {}", reason);
        if (SVController.getStaticConf().isStateTransferEnabled() && dt.getRecoverer() != null
                && reason == PolynomialCreationReason.RECOVERY) {
            if (onGoingRecoveryRequests.containsKey(id))
                sendRecoveryState(onGoingRecoveryRequests.remove(id), point);
            else
                recoveryPoints.put(id, point);
        }
    }

    @Override
    public void SMReplyDeliver(SMMessage msg, boolean isBFT) {
        try {
            lockTimer.lock();
            RecoverySMMessage recoveryMessage = (RecoverySMMessage)msg;
            logger.debug("State up to cid {} from {} with id {}", msg.getCID(),
                    msg.getSender(), recoveryMessage.getId());
            logger.debug("waitingCID: {}" , waitingCID);
            if (!SVController.getStaticConf().isStateTransferEnabled())
                return;
            int currentRegency = -1;
            int currentLeader = -1;
            View currentView = null;
            if (!appStateOnly) {
                senderRegencies.put(msg.getSender(), msg.getRegency());
                senderLeaders.put(msg.getSender(), msg.getLeader());
                senderViews.put(msg.getSender(), msg.getView());
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

            if (!isValidState((RecoveryApplicationState) recoveryMessage.getState())) { //TODO store deserialized state
                logger.debug("{} sent me invalid state", msg.getSender());
                return;
            }

            logger.debug("{} sent me valid state", msg.getSender());
            senderStates.put(msg.getSender(), msg.getState());

            if (!enoughReplies())
                return;
            logger.debug("More than f states confirmed");
            if (currentRegency == -1 || currentLeader == -1 || currentView == null) {
                if ((SVController.getCurrentViewN() / 2) < getReplies()) {
                    waitingCID = -1;
                    reset();

                    if (stateTimer != null)
                        stateTimer.cancel();

                    if (appStateOnly)
                        requestState();
                } else if ((SVController.getCurrentViewN() - SVController.getCurrentViewF()) <= getReplies()) {
                    logger.debug("Could not obtain the state, retrying");
                    reset();
                    if (stateTimer != null)
                        stateTimer.cancel();
                    waitingCID = -1;
                    requestState();
                } else
                    logger.debug("State transfer not yet finished");
                return;
            }
            logger.debug("Restoring state");
            state = recoverState(senderStates.values());
            if (state == null) {
                logger.debug("Failed to restore state. Retrying");
                reset();

                if (stateTimer != null)
                    stateTimer.cancel();

                if (appStateOnly)
                    requestState();
                return;
            }
            logger.debug("State restored");

            tomLayer.getSynchronizer().getLCManager().setLastReg(currentRegency);
            tomLayer.getSynchronizer().getLCManager().setNextReg(currentRegency);
            tomLayer.getSynchronizer().getLCManager().setNewLeader(currentLeader);
            tomLayer.execManager.setNewLeader(currentLeader);

            // I might have timed out before invoking the state transfer, so
            // stop my re-transmission of STOP messages for all regencies up to the current one
            if (currentRegency > 0) {
                logger.debug("Removing STOP retransmissions up to regency {}", currentLeader);
                tomLayer.getSynchronizer().removeSTOPretransmissions(currentRegency - 1);
            }
            //if (currentRegency > 0)
            //    tomLayer.requestsTimer.setTimeout(tomLayer.requestsTimer.getTimeout() * (currentRegency * 2));

            logger.debug("trying to acquire deliverLock");
            dt.deliverLock();
            logger.debug("deliverLock acquired");
            waitingCID = -1;
            dt.update(state);

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

            dt.canDeliver();
            dt.deliverUnlock();

            reset();

            logger.info("I updated the state!");

            tomLayer.requestsTimer.Enabled(true);
            tomLayer.requestsTimer.startTimer();
            if (stateTimer != null) {
                stateTimer.cancel();
            }

            if (appStateOnly) {
                appStateOnly = false;
                tomLayer.getSynchronizer().resumeLC();
            }
        } finally {
            lockTimer.unlock();
        }
    }

    private boolean isValidState(RecoveryApplicationState state) {
        Commitments recoveryCommitments = state.getTransferPolynomialCommitments();
        if (state.hasState()) {
            ConfidentialSnapshot recoverySnapshot = ConfidentialSnapshot.deserialize(state.getState());
            if (recoverySnapshot == null)
                return false;
            if (recoverySnapshot.getShares() != null) {
                for (VerifiableShare share : recoverySnapshot.getShares()) {
                    Commitments commitments = commitmentScheme.sumCommitments(share.getCommitments(), recoveryCommitments);
                    if (!commitmentScheme.checkValidity(share.getShare(), commitments))
                        return false;
                }
            }
        }

        CommandsInfo[] recoveryLog = state.getMessageBatches();
        for (CommandsInfo commandsInfo : recoveryLog) {
            for (byte[] command : commandsInfo.commands) {
                Request request = Request.deserialize(command);
                if (request == null)
                    return false;
                if (request.getShares() != null) {
                    for (VerifiableShare share : request.getShares()) {
                        Commitments commitments = commitmentScheme.sumCommitments(share.getCommitments(), recoveryCommitments);
                        if (!commitmentScheme.checkValidity(share.getShare(), commitments))
                            return false;
                    }
                }
            }
        }
        return true;
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
                    recoveredCommands[i] = commandToRecover[i];
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

    private void sendRecoveryState(RecoverySMMessage recoveryMessage, VerifiableShare recoveryPoint) {
        logger.debug("Creating recovery state up to CID {} for {} with id {}", recoveryMessage.getCID(),
                recoveryMessage.getSender(), recoveryMessage.getId());
        DefaultApplicationState appState = (DefaultApplicationState)dt.getRecoverer().getState(recoveryMessage.getCID(), true);
        if (appState == null) {
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

        RecoverySMMessage response = new RecoverySMMessage(
                SVController.getStaticConf().getProcessId(),
                appState.getLastCID(),
                TOMUtil.SM_REPLY,
                recoveryState,
                SVController.getCurrentView(),
                tomLayer.getSynchronizer().getLCManager().getLastReg(),
                recoveryMessage.getLeader(),
                recoveryMessage.getId()
        );

        logger.info("Sending recovery state up to {} to {} with id {}", recoveryState.getLastCID(),
                recoveryMessage.getSender(), recoveryMessage.getId());
        tomLayer.getCommunication().send(new int[] {recoveryMessage.getSender()}, response);
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
                        BigInteger share = y.add(shareToRecover.getShare().getShare());
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
            return new ConfidentialSnapshot(snapshot.getPlainData());
        byte[] plainData = snapshot.getPlainData();
        VerifiableShare[] shares = snapshot.getShares();
        int numShares = shares.length;
        VerifiableShare[] recoveryShares = new VerifiableShare[numShares];
        BigInteger shareholder = recoveryPoint.getShare().getShareholder();
        BigInteger y = recoveryPoint.getShare().getShare();
        VerifiableShare shareToRecover;

        for (int i = 0; i < numShares; i++) {
            shareToRecover = shares[i];
            BigInteger share = y.add(shareToRecover.getShare().getShare());
            recoveryShares[i] = new VerifiableShare(
                    new Share(shareholder, share),
                    shareToRecover.getCommitments(),
                    shareToRecover.getSharedData()
            );
        }

        return new ConfidentialSnapshot(plainData, recoveryShares);
    }
}
