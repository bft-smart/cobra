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
import vss.commitment.CommitmentScheme;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.PublicKey;
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
    private final Map<Integer, SMMessage> ongoingRecoveryRequests;
    private final Map<Integer, PolynomialRecovery> pendingRecoveryRequests;
    private final HashMap<Integer, Integer> sequenceNumbers;
    private final Timer refreshTimer;
    private TimerTask refreshTriggerTask;
    private long recoveryStartTime;
    private long renewalStartTime;
    private final Set<Integer> usedReplicas;
    private boolean isRefreshing;
    private RecoveryBlindedStateHandler recoveryBlindedStateHandler;
    private RecoveryBlindedStateSender recoveryStateSender;
    private ResharingBlindedStateSender resharingStateSender;
    private ReconfigurationParameters reconfigurationParameters;
    private final PolynomialStorage resharingNewGroupPoints;
    private int processId;

    public ConfidentialStateManager() {
        lockTimer = new ReentrantLock();
        ongoingRecoveryRequests = new ConcurrentHashMap<>();
        pendingRecoveryRequests = new ConcurrentHashMap<>();
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
        processId = tomLayer.controller.getStaticConf().getProcessId();
        tomLayer.requestsTimer.Enabled(false);
    }

    private int getRandomReplica() {
        if (true)
            return 3;
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
                processId,
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
                -> new COBRAStateCombiner(processId,
                commonState, shares, this).start();
        recoveryBlindedStateHandler = new RecoveryBlindedStateHandler(
                SVController,
                SERVER_RECOVERY_STATE_LISTENING_PORT,
                f,
                quorum,
                stateSenderReplica,
                confidentialityScheme,
                stateReceivedListener
        );
        recoveryBlindedStateHandler.start();

        logger.info("Sending request for state up to CID {} to {}", waitingCID,
                Arrays.toString(SVController.getCurrentViewOtherAcceptors()));
        tomLayer.getCommunication().send(SVController.getCurrentViewOtherAcceptors(), recoverySMMessage);

        tomLayer.requestsTimer.Enabled(false);

        TimerTask stateTask = new TimerTask() {
            @Override
            public void run() {
                logger.info("Timeout to retrieve state");
                SMMessage message = new DefaultSMMessage(
                        processId,
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
                logger.info("I do not have points for new group. Adding the request into the pending list.");
                pendingRecoveryRequests.put(request.getId(), request);
            } else {
                handlePolynomialRecoveryRequest(request, points);
            }
        } else if (msg instanceof PolynomialAccusation) {
            PolynomialAccusation accusation = (PolynomialAccusation) msg;
            int accuser = accusation.getAccuser();
            ProposalMessage[][] invalidProposals = accusation.getInvalidProposals();
            BigInteger[][][] invalidPoints = accusation.getInvalidPoints();
            Set<Integer> faultyProcesses = new HashSet<>(SVController.getCurrentViewF());
            for (int i = 0; i < invalidProposals.length; i++) {
                for (ProposalMessage proposalMessage : invalidProposals[i]) {
                    faultyProcesses.add(proposalMessage.getSender());
                }
                if (isInvalidAccusation(accuser, invalidProposals[i], invalidPoints[i])) {
                    logger.warn("Accuser {} sent me an invalid accusation", accuser);
                    System.exit(-1);
                }
            }

            if (recoveryStateSender != null) {
                recoveryStateSender.interrupt();
                recoveryStateSender = null;
            }
            logger.info("Received a valid polynomial accusation from {} of accuser {}", msg.getSender(),
                    accuser);
            removeFaultyProcesses(faultyProcesses);
            PolynomialRecovery polynomialRecoveryRequest = accusation.getPolynomialRecoveryRequest();
            if (polynomialRecoveryRequest != null && processId != 1) {//TODO for adversarial attack
                VerifiableShare[] points = resharingNewGroupPoints.getPoints(polynomialRecoveryRequest.getId());
                if (points == null) {
                    logger.info("I do not have points for new group. Adding the request into the pending list.");
                    pendingRecoveryRequests.put(polynomialRecoveryRequest.getId(), polynomialRecoveryRequest);
                } else {
                    handlePolynomialRecoveryRequest(polynomialRecoveryRequest, points);
                }
            }
        } else {
            logger.warn("Received unknown SM message type from {}", msg.getSender());
        }
    }

    @Override
    public void SMReplyDeliver(SMMessage msg, boolean isBFT) {
        if (msg instanceof PolynomialAccusation) {
            PolynomialAccusation accusation = (PolynomialAccusation)msg;
            int accuser = accusation.getAccuser();
            ProposalMessage[][] invalidProposals = accusation.getInvalidProposals();
            BigInteger[][][] invalidPoints = accusation.getInvalidPoints();
            Set<Integer> faultyProcesses = new HashSet<>(SVController.getCurrentViewF());
            for (int i = 0; i < invalidProposals.length; i++) {
                for (ProposalMessage proposalMessage : invalidProposals[i]) {
                    faultyProcesses.add(proposalMessage.getSender());
                }
                if (isInvalidAccusation(accuser, invalidProposals[i], invalidPoints[i])) {
                    logger.warn("Accuser {} sent me an invalid accusation", accuser);
                    System.exit(-1);
                }
            }
            logger.info("Accusation from {} is valid", accuser);
            recoveryBlindedStateHandler.interrupt();
            recoveryBlindedStateHandler = null;
            int[] sendAccusationTo = SVController.getCurrentViewOtherAcceptors();

            PolynomialAccusation accusationForBroadcast;
            PolynomialRecovery polynomialRecoveryRequest = null;
            if (resharingStateHandler == null) {
                accusationForBroadcast = new PolynomialAccusation(processId, TOMUtil.SM_REQUEST, invalidProposals,
                        invalidPoints, accuser);
            } else {
                logger.info("Restarting polynomial recovery");
                polynomialRecoveryRequest = createPolynomialRecoveryRequest(failedResharingPolynomialContext);
                accusationForBroadcast = new PolynomialAccusation(processId, TOMUtil.SM_REQUEST, invalidProposals,
                        invalidPoints, accuser, polynomialRecoveryRequest);
            }
            logger.info("Broadcasting accusation to {}", Arrays.toString(sendAccusationTo));
            tomLayer.getCommunication().send(sendAccusationTo, accusationForBroadcast);

            removeFaultyProcesses(faultyProcesses);

            if (resharingStateHandler == null) {
                logger.info("Restarting recovery");
                requestState();
            } else if (polynomialRecoveryRequest != null){
                startPolynomialRecovery(failedResharingPolynomialContext, polynomialRecoveryRequest);
            }
            return;
        }
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

    private void removeFaultyProcesses(Set<Integer> faultyProcesses) {
        int[] currentHonestProcesses = new int[SVController.getCurrentViewN() - faultyProcesses.size()];
        InetSocketAddress[] socketAddresses = new InetSocketAddress[SVController.getCurrentViewN() - faultyProcesses.size()];
        int index = 0;
        for (int currentViewAcceptor : SVController.getCurrentViewAcceptors()) {
            if (faultyProcesses.contains(currentViewAcceptor))
                continue;
            currentHonestProcesses[index] = currentViewAcceptor;
            socketAddresses[index] = SVController.getStaticConf().getRemoteAddress(currentViewAcceptor);
            index++;
        }
        logger.info("Remaining processes: {}", Arrays.toString(currentHonestProcesses));
        logger.info("Faulty processes: {}", faultyProcesses);
        SVController.reconfigureTo(new View(SVController.getCurrentViewId() + 1, currentHonestProcesses,
                SVController.getCurrentViewF(), socketAddresses));

        logger.info("Updating connections");
        tomLayer.getCommunication().updateServersConnections();

        for (int faultyProcess : faultyProcesses) {
            if (processId == faultyProcess) {
                logger.info("Shutting down");
                tomLayer.shutdown();
            }
        }
    }

    private void handlePolynomialRecoveryRequest(PolynomialRecovery request, VerifiableShare[] points) {
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

        triggerRecoveryStateTransfer(request, request.getStateSenderReplica(), request.getServerPort(),
                new byte[0], shares, commitments);
    }

    private void triggerRecoveryStateTransfer(SMMessage recoveryMessage, int fullStateSenderReplica, int serverPort,
                                              byte[] commonState, LinkedList<Share> shares,
                                              LinkedList<Commitment> commitments) {
        logger.info("Triggering recovery state transfer");
        boolean iAmStateSender =
                fullStateSenderReplica == processId;
        if (processId != 1 && processId != 4 && processId != 5) {//TODO for adversarial attack
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
        }
        int id = distributedPolynomialManager.createRecoveryPolynomialsFor(
                recoveryMessage.getSender(),
                confidentialityScheme.getShareholder(recoveryMessage.getSender()),
                SVController.getCurrentViewF(),
                SVController.getCurrentViewAcceptors(),
                shares.size()
        );
        ongoingRecoveryRequests.put(id, recoveryMessage);
    }

    private boolean isInvalidAccusation(int accuser, ProposalMessage[] invalidProposals, BigInteger[][] invalidPoints) {
        int nInvalidProposals = invalidProposals.length;
        for (int i = 0; i < nInvalidProposals; i++) {
            ProposalMessage invalidProposalMessage = invalidProposals[i];
            BigInteger[] invalidPoint = invalidPoints[i];
            Proposal[] proposals = invalidProposalMessage.getProposals();
            //verify signature
            byte[] cryptHash = computeCryptographicHash(invalidProposalMessage);

            PublicKey signingPublicKey = confidentialityScheme.getSigningPublicKeyFor(invalidProposalMessage.getSender());
            if (!TOMUtil.verifySignature(signingPublicKey, cryptHash, invalidProposalMessage.getSignature())) {
                return true;
            }
            //compare encrypted point
            for (int j = 0; j < invalidPoint.length; j++) {
                byte[] encryptedPoint = confidentialityScheme.encryptDataFor(accuser,
                        invalidPoint[i].toByteArray());
                if (!Arrays.equals(encryptedPoint, proposals[i].getPoints().get(accuser)))
                    return true;
            }
            //check the point
            CommitmentScheme commitmentScheme = confidentialityScheme.getCommitmentScheme();
            Share share = new Share();
            share.setShareholder(confidentialityScheme.getShareholder(accuser));
            Share propertyShare = new Share(confidentialityScheme.getShareholder(2), BigInteger.ZERO);//TODO correct this
            for (int j = 0; j < proposals.length; j++) {
                share.setShare(invalidPoint[i]);
                Commitment commitments = proposals[i].getCommitments();
                if (commitmentScheme.checkValidityWithoutPreComputation(share, commitments) &&
                        commitmentScheme.checkValidityWithoutPreComputation(propertyShare, commitments))
                    return true;
            }
        }

        return false;
    }

    @Override
    public void onRecoveryPolynomialsFailure(RecoveryPolynomialContext context) {
        int counter = (int) Arrays.stream(context.getPoints()).filter(Objects::isNull).count();
        logger.warn("Received {} invalid polynomials for recovery", counter);
        int size = context.getInvalidPolynomialsContexts().size();
        int[] ids = new int[size];
        int[] nPolynomials = new int[size];
        int index = 0;
        ProposalMessage[][] invalidProposals = new ProposalMessage[context.getInvalidPolynomialsContexts().size()][];
        BigInteger[][][] invalidPoints = new BigInteger[context.getInvalidPolynomialsContexts().size()][][];
        for (Map.Entry<Integer, InvalidPolynomialContext> entry : context.getInvalidPolynomialsContexts().entrySet()) {
            ids[index] = entry.getKey();
            nPolynomials[index] = entry.getValue().getNInvalidPolynomials();
            invalidProposals[index] = entry.getValue().getInvalidProposals();
            invalidPoints[index] = entry.getValue().getInvalidPoints();
            index++;
        }

        logger.debug("Invalid polynomial ids: {}", Arrays.toString(ids));
        logger.debug("Number of invalid polynomials per id: {}", Arrays.toString(nPolynomials));
        PolynomialAccusation accusation = new PolynomialAccusation(processId,
                TOMUtil.SM_REPLY, invalidProposals, invalidPoints, processId);
        SMMessage smMessage = ongoingRecoveryRequests.get(context.getInitialId());
        logger.info("Sending accusation to {}", smMessage.getSender());
        tomLayer.getCommunication().send(new int[]{smMessage.getSender()}, accusation);
    }

    @Override
    public void onRecoveryPolynomialsCreation(RecoveryPolynomialContext context) {
        logger.debug("Received {} polynomials for recovery", context.getNPolynomials());
        if (ongoingRecoveryRequests.containsKey(context.getInitialId())
                && processId != 1 && processId != 4 && processId != 5) {//TODO for adversarial attack
            SMMessage recoveryMessage = ongoingRecoveryRequests.remove(context.getInitialId());
            if (recoveryMessage instanceof DefaultSMMessage) {
                RecoveryStateServerSMMessage response;
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
                if (recoveryStateSender != null) {
                    recoveryStateSender.setBlindingShares(context.getPoints());
                    recoveryStateSender = null;
                }
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
        boolean iAmStateSender = leader == processId;

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

    private ResharingPolynomialContext failedResharingPolynomialContext;

    @Override
    public void onResharingPolynomialsFailure(ResharingPolynomialContext context) {
        failedResharingPolynomialContext = context;
        int[] newMembers = context.getNewMembers();
        if (!Utils.isIn(processId, newMembers)) {
            logger.warn("Received invalid polynomials for resharing but I am not in new view.");
            System.exit(0);
        }
        VerifiableShare[] pointsForNewGroup = context.getPointsForNewGroup();
        int counter = (int) Arrays.stream(pointsForNewGroup).filter(Objects::isNull).count();
        logger.warn("Received {} invalid polynomials for resharing", counter);

        PolynomialRecovery request = createPolynomialRecoveryRequest(context);
        startPolynomialRecovery(context, request);

        logger.info("Sending polynomial recovery request to {}", Arrays.toString(SVController.getCurrentViewOtherAcceptors()));
        tomLayer.getCommunication().send(SVController.getCurrentViewOtherAcceptors(), request);
    }

    private void startPolynomialRecovery(ResharingPolynomialContext context, PolynomialRecovery request) {
        VerifiableShare[] pointsForNewGroup = context.getPointsForNewGroup();
        int[] ids = request.getPolynomialInitialIds();
        int f = SVController.getCurrentViewF();
        int quorum =  f * 2 + 1;
        StateReceivedListener stateReceivedListener = (commonState, shares) -> {
            logger.info("------------>>>>>> Received recovered polynomial points");
            Iterator<VerifiableShare> it = shares.iterator();
            for (int id : ids) {
                pointsForNewGroup[id] = it.next();
            }

            isRefreshing = true;
            resharingStateSender.interrupt();
            resharingStateSender = null;
            resharingStateHandler.setRefreshShares(context.getPointsForNewGroup());
            resharingNewGroupPoints.putPoints(context.getInitialId(), context.getPointsForNewGroup());
        };
        recoveryBlindedStateHandler = new RecoveryBlindedStateHandler(
                SVController,
                SERVER_RECOVERY_STATE_LISTENING_PORT,
                f,
                quorum,
                3,
                confidentialityScheme,
                stateReceivedListener
        );
        recoveryBlindedStateHandler.start();
    }

    private PolynomialRecovery createPolynomialRecoveryRequest(ResharingPolynomialContext context) {
        int stateSenderReplica = 3;
        int size = context.getInvalidPolynomialsContexts().size();
        int[] ids = new int[size];
        int[] nPolynomials = new int[size];
        int index = 0;
        for (Map.Entry<Integer, InvalidPolynomialContext> entry : context.getInvalidPolynomialsContexts().entrySet()) {
            ids[index] = entry.getKey();
            nPolynomials[index] = entry.getValue().getNInvalidPolynomials();
            index++;
        }
        logger.debug("Invalid polynomial ids: {}", Arrays.toString(ids));
        logger.debug("Number of invalid polynomials per id: {}", Arrays.toString(nPolynomials));
        logger.info("Replica {} will send full recovery polynomial state", stateSenderReplica);

        return new PolynomialRecovery(context.getInitialId(), processId, stateSenderReplica,
                SERVER_RECOVERY_STATE_LISTENING_PORT, ids, nPolynomials);
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
        if (Utils.isIn(processId, oldMembers)) {
            if (processId != 1 && processId != 4 && processId != 5) //TODO for adversarial attack
                resharingStateSender.setBlindingShares(context.getPointsForOldGroup());
        }
        if (Utils.isIn(processId, newMembers)) {
            resharingStateHandler.setRefreshShares(context.getPointsForNewGroup());
            resharingNewGroupPoints.putPoints(context.getInitialId(), context.getPointsForNewGroup());
            if (pendingRecoveryRequests.containsKey(context.getInitialId()))
                handlePolynomialRecoveryRequest(pendingRecoveryRequests.remove(context.getInitialId()), context.getPointsForNewGroup());
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
                logger.debug("Waiting for more states");
                return;
            }

            logger.debug("More than f states confirmed");

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

            logger.debug("Updating state");
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
        resharingStateHandler.interrupt();
        resharingStateHandler = null;
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
        int stateSenderReplica = 0;//group[consensusId % group.length]; TODO for adversarial attack [uncomment to make it correct]
        logger.info("Replica {} will send full reshared state", stateSenderReplica);
        int f = reconfigurationParameters.getOldF();
        int quorum = 2 * reconfigurationParameters.getOldF() + 1;
        renewalStartTime = System.nanoTime();
        StateReceivedListener stateReceivedListener = (commonState, shares)
                -> new COBRAStateCombiner(processId,
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
        if (processId != 1 && processId != 4 && processId != 5)//TODO for adversarial attack
            startResharing(consensusId, stateSenderReplica, f, group,
                reconfigurationParameters.getNewF(), group);
    }

    private ResharingBlindedStateHandler resharingStateHandler;

    private void setRefreshTimer() {
        if (Configuration.getInstance().isRenewalActive())
            throw new UnsupportedOperationException("Send reconfiguration request from admin client for the same threshold to use refresh.");
        StateReceivedListener stateReceivedListener = (commonState, shares)
                -> new COBRAStateCombiner(processId,
                commonState, shares, this).start();
        refreshTriggerTask = new TimerTask() {
            @Override
            public void run() {
                renewalStartTime = System.nanoTime();
                int f = SVController.getCurrentViewF();
                int[] currentGroup = SVController.getCurrentViewAcceptors();
                int quorum = 2 * f + 1;
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

    private byte[] computeCryptographicHash(ProposalMessage message) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeInt(message.getSender());
            out.writeInt(message.getId());
            for (Proposal proposal : message.getProposals()) {
                int[] members = new int[proposal.getPoints().size()];
                int i = 0;
                Map<Integer, byte[]> points = proposal.getPoints();
                for (int member : points.keySet()) {
                    members[i++] = member;
                }
                Arrays.sort(members);
                for (int member : members) {
                    out.write(member);
                    out.write(points.get(member));
                }
                proposal.getCommitments().writeExternal(out);
            }
            out.flush();
            bos.flush();
            return TOMUtil.computeHash(bos.toByteArray());
        } catch (IOException e) {
            logger.error("Failed to create cryptographic hash of the proposal from {}", message.getSender(), e);
            return null;
        }
    }
}
