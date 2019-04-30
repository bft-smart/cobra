package confidential.server;

import bftsmart.statemanagement.ApplicationState;
import bftsmart.statemanagement.StateManager;
import bftsmart.tom.MessageContext;
import bftsmart.tom.ReplicaContext;
import bftsmart.tom.server.Recoverable;
import bftsmart.tom.server.SingleExecutable;
import confidential.ConfidentialMessage;
import confidential.MessageType;
import confidential.polynomial.DistributedPolynomial;
import confidential.statemanagement.ConfidentialStateLog;
import confidential.statemanagement.ConfidentialStateManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.facade.SecretSharingException;
import vss.secretsharing.PrivatePublishedShares;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.util.concurrent.locks.ReentrantLock;

public abstract class ConfidentialRecoverable implements SingleExecutable, Recoverable {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private ServerConfidentialityScheme confidentialityScheme;
    private final int processId;
    private ReplicaContext replicaContext;
    private ConfidentialStateLog log;
    private ReentrantLock stateLock;
    private ConfidentialStateManager stateManager;
    private DistributedPolynomial distributedPolynomial;

    public ConfidentialRecoverable(int processId) {
        this.processId = processId;
    }

    @Override
    public void setReplicaContext(ReplicaContext replicaContext) {
        logger.debug("setting replica context");
        this.replicaContext = replicaContext;
        this.stateLock = new ReentrantLock();
        InterServersCommunication serversCommunication = new InterServersCommunication(
                replicaContext.getServerCommunicationSystem(), replicaContext.getSVController());
        distributedPolynomial = new DistributedPolynomial(serversCommunication, replicaContext.getSVController());
        try {
            this.confidentialityScheme = new ServerConfidentialityScheme(processId, replicaContext.getCurrentView());
            if (this.log == null)
                this.log = initLog();
            getStateManager().askCurrentConsensusId();
        } catch (SecretSharingException e) {
            logger.error("Failed to initialize ServerConfidentialityScheme", e);
        }
    }

    private ConfidentialStateLog initLog() {
        if (!replicaContext.getStaticConfiguration().isToLog())
            return null;
        if (replicaContext.getStaticConfiguration().logToDisk()) {
            logger.error("Log to disk not implemented");
            return null;
        }
        logger.info("Logging to memory");
        return new ConfidentialStateLog();
    }

    @Override
    public ApplicationState getState(int cid, boolean sendState) {
        return null;
    }

    @Override
    public int setState(ApplicationState state) {
        return 0;
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

    }

    @Override
    public byte[] executeOrdered(byte[] command, MessageContext msgCtx) {
        Message request = deserializeRequest(command, msgCtx);
        if (request == null)
            return null;
        if (request.getMessageType() == MessageType.APPLICATION) {

            return new byte[0];
        }
        ClientMessage clientMessage = (ClientMessage)request;
        stateLock.lock();
        ConfidentialMessage response = appExecuteOrdered(clientMessage.getPlainData(), clientMessage.getShares(), msgCtx);
        stateLock.unlock();


        return response.serialize();
    }

    @Override
    public byte[] executeUnordered(byte[] command, MessageContext msgCtx) {
        Message request = deserializeRequest(command, msgCtx);
        if (request == null)
            return null;
        if (request.getMessageType() == MessageType.APPLICATION) {

            return new byte[0];
        }
        ClientMessage clientMessage = (ClientMessage)request;
        return appExecuteUnordered(clientMessage.getPlainData(), clientMessage.getShares(), msgCtx).serialize();
    }

    public abstract ConfidentialMessage appExecuteOrdered(byte[] plainData, VerifiableShare[] shares, MessageContext msgCtx);

    public abstract ConfidentialMessage appExecuteUnordered(byte[] plainData, VerifiableShare[] shares, MessageContext msgCtx);

    private Message deserializeRequest(byte[] message, MessageContext msgCtx) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(message);
             ObjectInput in = new ObjectInputStream(bis)) {
            MessageType type = MessageType.getMessageType(in.read());
            Message result = null;
            switch (type) {
                case CLIENT:
                    int len = in.readInt();
                    byte[] plainData = null;
                    if (len != -1) {
                        plainData = new byte[len];
                        in.readFully(plainData);
                    }
                    len = in.readInt();
                    VerifiableShare[] shares = null;
                    if (len != -1) {
                        shares = new VerifiableShare[len];
                        PrivatePublishedShares publishedShares;
                        for (int i = 0; i < len; i++) {
                            publishedShares = new PrivatePublishedShares();
                            publishedShares.readExternal(in);
                            shares[i] = confidentialityScheme.extractShare(publishedShares);
                        }
                    }
                    result = new ClientMessage(type, plainData, shares);
                    break;
                case APPLICATION:
                    break;
            }
            return result;
        } catch (IOException | SecretSharingException e) {
            logger.warn("Failed to decompose request from {}", msgCtx.getSender(), e);
            return null;
        }
    }
}
