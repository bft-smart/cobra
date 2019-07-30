package confidential.server;

import bftsmart.reconfiguration.ReconfigureRequest;
import bftsmart.reconfiguration.ServerViewController;
import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.StateManager;
import bftsmart.tom.MessageContext;
import bftsmart.tom.ReplicaContext;
import bftsmart.tom.server.Recoverable;
import bftsmart.tom.server.SingleExecutable;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.MessageType;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.polynomial.DistributedPolynomial;
import confidential.statemanagement.ConfidentialSnapshot;
import confidential.statemanagement.ConfidentialStateLog;
import confidential.statemanagement.ConfidentialStateManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.facade.SecretSharingException;
import vss.secretsharing.PrivatePublishedShares;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

public abstract class ConfidentialRecoverable implements SingleExecutable, Recoverable {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private ServerConfidentialityScheme confidentialityScheme;
    private final int processId;
    private ReplicaContext replicaContext;
    private ConfidentialStateLog log;
    private ReentrantLock stateLock;
    private ReentrantLock logLock;
    private ConfidentialStateManager stateManager;
    private InterServersCommunication interServersCommunication;
    private int checkpointPeriod;
    private List<byte[]> commands;
    private List<MessageContext> msgContexts;
    private int currentF;

    public ConfidentialRecoverable(int processId) {
        this.processId = processId;
        this.logLock = new ReentrantLock();
        this.commands = new ArrayList<>();
        this.msgContexts = new ArrayList<>();
    }

    @Override
    public void setReplicaContext(ReplicaContext replicaContext) {
        logger.debug("setting replica context");
        this.currentF = replicaContext.getSVController().getCurrentViewF();
        this.replicaContext = replicaContext;
        this.stateLock = new ReentrantLock();
        interServersCommunication = new InterServersCommunication(
                replicaContext.getServerCommunicationSystem(), replicaContext.getSVController());
        checkpointPeriod = replicaContext.getStaticConfiguration().getCheckpointPeriod();
        try {
            this.confidentialityScheme = new ServerConfidentialityScheme(processId, replicaContext.getCurrentView());
            DistributedPolynomial distributedPolynomial = new DistributedPolynomial(processId, interServersCommunication,
                    confidentialityScheme.getCommitmentScheme(), confidentialityScheme.getField());
            new Thread(distributedPolynomial, "Distributed polynomial").start();
            stateManager.setDistributedPolynomial(distributedPolynomial);
            stateManager.setInterpolationStrategy(confidentialityScheme.getInterpolationStrategy());
            stateManager.setCommitmentScheme(confidentialityScheme.getCommitmentScheme());
            log = getLog();
            stateManager.askCurrentConsensusId();
        } catch (SecretSharingException e) {
            logger.error("Failed to initialize ServerConfidentialityScheme", e);
        }
    }

    private ConfidentialStateLog getLog() {
        if (log == null)
            log = initLog();
        return log;
    }

    private ConfidentialStateLog initLog() {
        if (!replicaContext.getStaticConfiguration().isToLog())
            return null;
        ConfidentialSnapshot snapshot = getConfidentialSnapshot();
        byte[] state = snapshot.serialize();
        if (replicaContext.getStaticConfiguration().logToDisk()) {
            logger.error("Log to disk not implemented");
            return null;
        }
        logger.info("Logging to memory");
        return new ConfidentialStateLog(processId, checkpointPeriod, state, TOMUtil.computeHash(state));
    }

    @Override
    public ApplicationState getState(int cid, boolean sendState) {
        logLock.lock();
        logger.debug("Getting state until CID {}", cid);
        ApplicationState state = (cid > -1 ? getLog().getApplicationState(cid, sendState)
                : new DefaultApplicationState());
        if (state == null ||
                (replicaContext.getStaticConfiguration().isBFT()
                        && state.getCertifiedDecision(replicaContext.getSVController()) == null))
            state = new DefaultApplicationState();
        logLock.unlock();
        return state;
    }

    @Override
    public int setState(ApplicationState recvState) {
        int lastCID = -1;
        if (recvState instanceof DefaultApplicationState) {
            DefaultApplicationState state = (DefaultApplicationState)recvState;
            logger.info("I'm going to update myself from CID {} to CID {}",
                    state.getLastCheckpointCID(), state.getLastCID());

            stateLock.lock();
            logLock.lock();
            log.update(state);

            int lastCheckpointCID = log.getLastCheckpointCID();
            lastCID = log.getLastCID();


            if (state.getSerializedState() != null) {
                logger.info("Installing snapshot up to CID {}", lastCheckpointCID);
                ConfidentialSnapshot snapshot = ConfidentialSnapshot.deserialize(state.getSerializedState());
                installConfidentialSnapshot(snapshot);
            }

            for (int cid = lastCheckpointCID + 1; cid <= lastCID; cid++) {
                try {
                    logger.debug("Processing and verifying batched requests for CID {}", cid);
                    CommandsInfo cmdInfo = log.getMessageBatch(cid);
                    if (cmdInfo == null) {
                        logger.warn("Consensus {} is null", cid);
                        continue;
                    }
                    byte[][] commands = cmdInfo.commands;
                    MessageContext[] msgCtx = cmdInfo.msgCtx;

                    if (commands == null || msgCtx == null || msgCtx[0].isNoOp())
                        continue;

                    for (int i = 0; i < commands.length; i++) {
                        Request request = Request.deserialize(commands[i]);
                        if (request == null) {
                            logger.warn("Request is null");
                            continue;
                        }
                        if (request.getType() == MessageType.APPLICATION) {
                            logger.debug("Ignoring application request");
                            continue;
                        }
                        appExecuteOrdered(request.getPlainData(), request.getShares(), msgCtx[i]);
                    }
                } catch (Exception e) {
                    logger.error("Failed to process and verify batched requests for CID {}", cid, e);
                    if (e instanceof ArrayIndexOutOfBoundsException) {
                        logger.info("Last checkpoint CID: {}", lastCheckpointCID);
                        logger.info("Last CID: {}", lastCID);
                        logger.info("Number of messages expected to be in the batch: {}", (log.getLastCID() - log.getLastCheckpointCID() + 1));
                        logger.info("Number of messages in the batch: {}", log.getMessageBatches().length);
                    }
                }
            }
            logLock.unlock();
            stateLock.unlock();
        }
        return lastCID;
    }

    @Override
    public StateManager getStateManager() {
        if (stateManager == null)
            stateManager = new ConfidentialStateManager();
        return stateManager;
    }

    @Override
    public void Op(int CID, byte[] requests, MessageContext msgCtx) {

    }

    @Override
    public void noOp(int CID, byte[][] operations, MessageContext[] msgCtx) {
        logger.debug("NoOp");
        //for (int i = 0; i < msgCtx.length; i++)
        //    logRequest(operations[i], msgCtx[i]);

        for (byte[] operation : operations) {
            Object obj = TOMUtil.getObject(operation);
            if (obj instanceof ReconfigureRequest) {
                logger.info("Reconfiguration");
                ReconfigureRequest reconfigureRequest = (ReconfigureRequest) obj;
                for (Integer key : reconfigureRequest.getProperties().keySet()) {
                    String value = reconfigureRequest.getProperties().get(key);
                    if (key == ServerViewController.CHANGE_F) {
                        int f = Integer.valueOf(value);
                        if (currentF < f) {
                            logger.info("Increasing f. {}->{}", currentF, f);
                        } else if (currentF > f) {
                            logger.info("Reducing f. {}->{}", currentF, f);
                        }
                        currentF = f;
                    }
                }
            }
        }
    }

    @Override
    public byte[] executeOrdered(byte[] command, MessageContext msgCtx) {
        Request request = preprocessRequest(command, msgCtx);
        if (request == null)
            return null;
        byte[] preprocessedCommand = request.serialize();
        byte[] response;
        if (request.getType() == MessageType.APPLICATION) {
            logger.debug("Received application ordered message of {} in CID {}. Regency: {}", msgCtx.getSender(),
                    msgCtx.getConsensusId(), msgCtx.getRegency());
            interServersCommunication.messageReceived(request.getPlainData(), msgCtx);
            response = new byte[0];
        } else {
            stateLock.lock();
            response = appExecuteOrdered(request.getPlainData(), request.getShares(), msgCtx).serialize();
            stateLock.unlock();
        }
        logRequest(preprocessedCommand, msgCtx);

        return response;
    }

    @Override
    public byte[] executeUnordered(byte[] command, MessageContext msgCtx) {
        Request request = preprocessRequest(command, msgCtx);
        if (request == null)
            return null;
        if (request.getType() == MessageType.APPLICATION) {
            logger.debug("Received application unordered message of {} in CID {}", msgCtx.getSender(), msgCtx.getConsensusId());
            interServersCommunication.messageReceived(request.getPlainData(), msgCtx);
            return new byte[0];
        }

        return appExecuteUnordered(request.getPlainData(), request.getShares(), msgCtx).serialize();
    }

    public abstract ConfidentialMessage appExecuteOrdered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx);

    public abstract ConfidentialMessage appExecuteUnordered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx);

    public abstract ConfidentialSnapshot getConfidentialSnapshot();

    public abstract void installConfidentialSnapshot(ConfidentialSnapshot snapshot);

    private Request preprocessRequest(byte[] message, MessageContext msgCtx) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(message);
             ObjectInput in = new ObjectInputStream(bis)) {
            MessageType type = MessageType.getMessageType(in.read());
            Request result = null;
            int len;
            byte[] plainData = null;
            switch (type) {
                case CLIENT:
                    len = in.readInt();
                    if (len != -1) {
                        plainData = new byte[len];
                        in.readFully(plainData);
                    }
                    len = in.readInt();
                    ConfidentialData[] shares = null;
                    if (len != -1) {
                        shares = new ConfidentialData[len];
                        PrivatePublishedShares publishedShares;
                        for (int i = 0; i < len; i++) {
                            publishedShares = new PrivatePublishedShares();
                            publishedShares.readExternal(in);
                            shares[i] = new ConfidentialData(confidentialityScheme.extractShare(publishedShares));
                        }
                    }
                    result = new Request(type, plainData, shares);
                    break;
                case APPLICATION:
                    len = in.readInt();
                    plainData = new byte[len];
                    in.readFully(plainData);
                    result = new Request(type, plainData);
                    break;
            }
            return result;
        } catch (IOException | SecretSharingException e) {
            logger.warn("Failed to decompose request from {}", msgCtx.getSender(), e);
            return null;
        }
    }

    private void saveState(byte[] snapshot, int lastCID) {
        logLock.lock();
        logger.debug("Saving state of CID {}", lastCID);

        log.newCheckpoint(snapshot, TOMUtil.computeHash(snapshot), lastCID);

        logLock.unlock();
        logger.debug("Finished saving state of CID {}", lastCID);
    }

    private void saveCommands(byte[][] commands, MessageContext[] msgCtx) {
        if (commands.length != msgCtx.length) {
            logger.debug("----SIZE OF COMMANDS AND MESSAGE CONTEXTS IS DIFFERENT----");
            logger.debug("----COMMANDS: {}, CONTEXTS: {} ----", commands.length, msgCtx.length);
        }
        logger.debug("Saving Commands of client {} with cid {}", msgCtx[0].getSender(), msgCtx[0].getConsensusId());
        logLock.lock();

        int cid = msgCtx[0].getConsensusId();
        int batchStart = 0;
        for (int i = 0; i <= msgCtx.length; i++) {
            if (i == msgCtx.length) { // the batch command contains only one command or it is the last position of the array
                byte[][] batch = Arrays.copyOfRange(commands, batchStart, i);
                MessageContext[] batchMsgCtx = Arrays.copyOfRange(msgCtx, batchStart, i);
                log.addMessageBatch(batch, batchMsgCtx, cid);
            } else {
                if (msgCtx[i].getConsensusId() > cid) { // saves commands when the CID changes or when it is the last batch
                    byte[][] batch = Arrays.copyOfRange(commands, batchStart, i);
                    MessageContext[] batchMsgCtx = Arrays.copyOfRange(msgCtx, batchStart, i);
                    log.addMessageBatch(batch, batchMsgCtx, cid);
                    cid = msgCtx[i].getConsensusId();
                    batchStart = i;
                }
            }
        }
        logger.debug("Log size: " + log.getNumBatches());
        logLock.unlock();
    }

    private void logRequest(byte[] command, MessageContext msgCtx) {
        int cid = msgCtx.getConsensusId();
        commands.add(command);
        msgContexts.add(msgCtx);

        if (!msgCtx.isLastInBatch()) {
            //logger.debug("Not last in the batch");
            return;
        }

        if (cid > 0 && (cid % checkpointPeriod) == 0) {
            logger.info("Performing checkpoint for consensus " + cid);
            stateLock.lock();
            ConfidentialSnapshot snapshot = getConfidentialSnapshot();
            stateLock.unlock();
            saveState(snapshot.serialize(), cid);
        } else {
            saveCommands(commands.toArray(new byte[0][]), msgContexts.toArray(new MessageContext[0]));
        }
        getStateManager().setLastCID(cid);
        commands.clear();
        msgContexts.clear();
    }
}
