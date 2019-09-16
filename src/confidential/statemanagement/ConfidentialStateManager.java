package confidential.statemanagement;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.reconfiguration.views.View;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.SMMessage;
import bftsmart.statemanagement.StateManager;
import bftsmart.tom.MessageContext;
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
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

public class ConfidentialStateManager extends StateManager implements PolynomialCreationListener, ReconstructionCompleted {
    private static final long REFRESH_PERIOD = 150_000;
    private static final boolean RENEWAL = false;
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
                stateSenderReplica
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
                stateSenderReplica
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
        logger.debug("Received recovery request from {}", msg.getSender());
        if (msg instanceof DefaultSMMessage) {
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
            logger.warn("Received unknown SM message type");
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

            if (stateRecoveryHandlerThread.isAlive()) {
                logger.debug("Submitting state recovery info from {} to recovery", msg.getSender());
                stateRecoveryHandlerThread.deliverRecoveryState(recoverySMMessage);
            } else {
                logger.debug("State recovery already has finished");
                //onReconstructionCompleted(false, recoverySMMessage);
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
                sendRecoveryState((DefaultSMMessage) onGoingRecoveryRequests.remove(context.getId()), point);
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


            waitingCID = consensusId;// will make DeliveryThread to stop waiting for state

            logger.info("Stopping execution manager");
            tomLayer.execManager.stop();
            int lastExec = tomLayer.getLastExec();
            int inExec = tomLayer.getInExec();

            dt.deliverLock();

            int currentRegency = tomLayer.getSynchronizer().getLCManager().getLastReg();
            if (currentRegency > 0) {
                logger.debug("Removing STOP retransmissions up to regency {}", currentRegency);
                tomLayer.getSynchronizer().removeSTOPretransmissions(currentRegency - 1);
            }

            //logger.debug("Getting state up to {}", consensusId);
            DefaultApplicationState appState = (DefaultApplicationState) dt.getRecoverer().getState(consensusId, true);
            if (appState == null) {
                logger.debug("Something went wrong while retrieving state up to {}", consensusId);
                return;
            }

            ApplicationState refreshedState = refreshState(point, appState);
            if (refreshedState != null) {
                logger.info("Updating state");
                dt.update(refreshedState);

                logger.info("Restarting execution manager");
                tomLayer.setLastExec(lastExec);
                tomLayer.setInExec(inExec);
                execManager.restart();

                //logger.info("Modifying lastExec to {}", lastExec);
                //tomLayer.setLastExec(lastExec);

                logger.debug("Processing out of context messages");
                tomLayer.processOutOfContext();
                logger.debug("Finished processing out of context messages");
            }
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
        int myPort = 5000 + SVController.getStaticConf().getProcessId();
        logger.debug("Sending sequence number {} with the state", sequenceNumber.get());
        RecoveryStateServerSMMessage response = new RecoveryStateServerSMMessage(
                SVController.getStaticConf().getProcessId(),
                appState.getLastCID(),
                TOMUtil.SM_REPLY,
                SVController.getCurrentView(),
                tomLayer.getSynchronizer().getLCManager().getLastReg(),
                recoveryMessage.getLeader(),
                sequenceNumber.get(),
                SVController.getCurrentView().getAddress(SVController.getStaticConf().getProcessId()).getAddress().getHostAddress(),
                myPort
        );

        try {
            logger.debug("Starting recovery state sender server");
            new RecoveryStateSender(
                    myPort,
                    SVController.getCurrentView().getAddress(recoveryMessage.getSender()).getAddress().getHostAddress(),
                    appState,
                    recoveryPoint,
                    distributedPolynomial.getField(),
                    SVController,
                    SVController.getStaticConf().getProcessId() == recoveryMessage.getStateSenderReplica()
            ).start();
        } catch (Exception e) {
            e.printStackTrace();
        }

        logger.info("Sending recovery state sender server info to {}", recoveryMessage.getSender());
        tomLayer.getCommunication().send(new int[]{recoveryMessage.getSender()}, response);
        logger.info("Recovery state sender server info sent");

        /*RecoveryApplicationState recoveryState = createRecoverState(appState, recoveryPoint);
        if (recoveryState == null) {
            return;
        }
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

        logger.info("Sending recovery state up to cid {} to {} of size {} bytes and {} shares", recoveryState.getLastCID(),
                recoveryMessage.getSender(), recoveryState.getCommonState().length, recoveryState.getShares().size());
        tomLayer.getCommunication().send(new int[] {recoveryMessage.getSender()}, response);
        logger.info("Recovery state sent");*/
    }

    private RecoveryApplicationState createRecoverState(DefaultApplicationState state, VerifiableShare transferPoint) {
        BigInteger field = distributedPolynomial.getField();
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            CommandsInfo[] log = state.getMessageBatches();
            out.writeInt(log == null ? -1 : log.length);
            LinkedList<Share> shares = new LinkedList<>();
            byte[] b;
            if (log != null) {
                for (CommandsInfo commandsInfo : log) {
                    byte[][] commands = commandsInfo.commands;
                    MessageContext[] msgCtx = commandsInfo.msgCtx;
                    serializeMessageContext(out, msgCtx);
                    out.writeInt(commands.length);
                    for (byte[] command : commands) {
                        Request request = Request.deserialize(command);
                        if (request == null || request.getShares() == null) {
                            out.writeInt(-1);
                            out.writeInt(command.length);
                            out.write(command);
                        } else {
                            out.writeInt(request.getShares().length);
                            for (ConfidentialData share : request.getShares()) {
                                b = share.getShare().getSharedData();
                                out.writeInt(b == null ? -1 : b.length);
                                if (b != null)
                                    out.write(b);
                                share.getShare().getCommitments().writeExternal(out);

                                Share transferShare = share.getShare().getShare();
                                transferShare.setShare(transferShare.getShare().add(transferPoint.getShare().getShare()).mod(field));
                                shares.add(transferShare);

                                out.writeInt(share.getPublicShares() == null ? -1 : share.getPublicShares().size());
                                if (share.getPublicShares() != null) {//writing public data
                                    for (VerifiableShare publicShare : share.getPublicShares()) {
                                        publicShare.writeExternal(out);
                                    }
                                }
                            }
                            request.setShares(null);
                            b = request.serialize();
                            if (b == null) {
                                logger.debug("Failed to serialize recovery Request");
                                return null;
                            }
                            out.writeInt(b.length);
                            out.write(b);
                        }
                    }
                }
            }

            if (state.hasState()) {
                ConfidentialSnapshot snapshot = ConfidentialSnapshot.deserialize(state.getSerializedState());
                if (snapshot != null) {
                    out.writeBoolean(true);
                    out.writeInt(snapshot.getPlainData() == null ? -1 : snapshot.getPlainData().length);
                    if (snapshot.getPlainData() != null)
                        out.write(snapshot.getPlainData());
                    out.writeInt(snapshot.getShares() == null ? -1 : snapshot.getShares().length);
                    if (snapshot.getShares() != null) {
                        for (ConfidentialData share : snapshot.getShares()) {
                            b = share.getShare().getSharedData();
                            out.writeInt(b == null ? -1 : b.length);
                            if (b != null)
                                out.write(b);
                            share.getShare().getCommitments().writeExternal(out);
                            Share transferShare = share.getShare().getShare();
                            transferShare.setShare(transferShare.getShare().add(transferPoint.getShare().getShare()).mod(field));
                            shares.add(transferShare);

                            out.writeInt(share.getPublicShares() == null ? -1 : share.getPublicShares().size());
                            if (share.getPublicShares() != null) {//writing public data
                                for (VerifiableShare publicShare : share.getPublicShares()) {
                                    publicShare.writeExternal(out);
                                }
                            }
                        }
                    }
                } else
                    out.writeBoolean(false);
            } else
                out.writeBoolean(false);

            out.flush();
            bos.flush();

            byte[] commonState = bos.toByteArray();
            //logger.debug("Common State: {}", commonState);

            return new RecoveryApplicationState(
                    commonState,
                    shares,
                    state.getLastCheckpointCID(),
                    state.getLastCID(),
                    SVController.getStaticConf().getProcessId(),
                    transferPoint.getCommitments()

            );

        } catch (IOException e) {
            logger.error("Failed to create Recovery State", e);
        }
        return null;
    }

    private void serializeMessageContext(ObjectOutputStream out, MessageContext[] msgCtx) throws IOException {
        out.writeInt(msgCtx == null ? -1 : msgCtx.length);
        if (msgCtx == null)
            return;
        for (MessageContext ctx : msgCtx) {
            out.writeInt(ctx.getSender());
            out.writeInt(ctx.getViewID());
            out.writeInt(ctx.getType().ordinal());
            out.writeInt(ctx.getSession());
            out.writeInt(ctx.getSequence());
            out.writeInt(ctx.getOperationId());
            out.writeInt(ctx.getReplyServer());
            out.writeInt(ctx.getSignature() == null ? -1 : ctx.getSignature().length);
            if (ctx.getSignature() != null)
                out.write(ctx.getSignature());

            out.writeLong(ctx.getTimestamp());
            out.writeInt(ctx.getRegency());
            out.writeInt(ctx.getLeader());
            out.writeInt(ctx.getConsensusId());
            out.writeInt(ctx.getNumOfNonces());
            out.writeLong(ctx.getSeed());
            out.writeInt(ctx.getProof() == null ? -1 : ctx.getProof().size());
            if (ctx.getProof() != null) {
                for (ConsensusMessage proof : ctx.getProof()) {
                    //out.writeInt(proof.getSender());
                    out.writeInt(proof.getNumber());
                    out.writeInt(proof.getEpoch());
                    out.writeInt(proof.getType());

                    out.writeInt(proof.getValue() == null ? -1 : proof.getValue().length);
                    if (proof.getValue() != null)
                        out.write(proof.getValue());
                    /*logger.debug("{}", proof.getProof());*/
                }
            }
            ctx.getFirstInBatch().wExternal(out);
            out.writeBoolean(ctx.isLastInBatch());
            out.writeBoolean(ctx.isNoOp());
            //out.writeBoolean(ctx.readOnly);

            out.writeInt(ctx.getNonces() == null ? -1 : ctx.getNonces().length);
            if (ctx.getNonces() != null)
                out.write(ctx.getNonces());
        }

    }
}
