package confidential.statemanagement;

import bftsmart.tom.MessageContext;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class ConfidentialStateLog {
    private Logger logger = LoggerFactory.getLogger("confidential");

    private CommandsInfo[] messageBatches; // batches received since the last checkpoint.
    private int lastCheckpointCID; // Consensus ID for the last checkpoint
    private byte[] state; // State associated with the last checkpoint
    private byte[] stateHash; // Hash of the state associated with the last checkpoint
    private int position; // next position in the array of batches to be written
    private int lastCID; // Consensus ID for the last messages batch delivered to the application
    private int id; //replica ID

    public ConfidentialStateLog(int id, int k, byte[]initialState, byte[] initialStateHash) {
        this.messageBatches = new CommandsInfo[k - 1];
        this.lastCheckpointCID = -1;
        this.state = initialState;
        this.stateHash = initialStateHash;
        this.position = 0;
        this.lastCID = -1;
        this.id = id;
    }

    public void newCheckpoint(byte[] state, byte[] stateHash, int lastConsensusId) {
        Arrays.fill(messageBatches, null); // removing previous messages
        position = 0;
        this.state = state;
        this.stateHash = stateHash;
        this.lastCheckpointCID = lastConsensusId;
        this.lastCID = lastConsensusId;
    }

    public int getLastCheckpointCID() {
        return lastCheckpointCID;
    }

    public int getLastCID() {
        return lastCID;
    }

    public byte[] getState() {
        return state;
    }

    public byte[] getStateHash() {
        return stateHash;
    }

    public void addMessageBatch(byte[][] commands, MessageContext[] msgCtx, int lastConsensusId) {
        if (position < messageBatches.length) {
            messageBatches[position] = new CommandsInfo(commands, msgCtx);
            position++;
            lastCID = lastConsensusId;
        }
    }

    public CommandsInfo getMessageBatch(int cid) {
        if (cid > lastCheckpointCID && cid <= lastCID)
            return messageBatches[cid - lastCheckpointCID - 1];
        return null;
    }

    public CommandsInfo[] getMessageBatches() {
        return messageBatches;
    }

    public int getNumBatches() {
        return position;
    }

    public DefaultApplicationState getApplicationState(int cid, boolean setState) {
        logger.info("CID requested: {}. Last checkpoint: {}. Last CID: {}", cid, lastCheckpointCID, lastCID);
        CommandsInfo[] batches = null;
        int lastCID = -1;
        if (cid >= lastCheckpointCID && cid <= this.lastCID) {
            logger.info("Constructing ApplicationState up until CID {}", cid);
            int size = cid - lastCheckpointCID;
            if (size > 0) {
                batches = Arrays.copyOf(messageBatches, size);
            }
            lastCID = cid;
            return new DefaultApplicationState(batches, lastCheckpointCID,
                    lastCID, (setState ? state : null), stateHash, id);
        }
        return null;
    }

    public void update(DefaultApplicationState transState) {
        CommandsInfo[] newMsgBatches = transState.getMessageBatches();
        if (newMsgBatches != null) {
            for (int i = 0; i < newMsgBatches.length; i++) {
                messageBatches[i] = newMsgBatches[i];
                lastCID = Math.max(lastCID, newMsgBatches[i].msgCtx[0].getConsensusId());
                position = Math.max(position, i + 1);
            }
        }
        this.lastCheckpointCID = transState.getLastCheckpointCID();
        this.state = transState.getState();
        this.stateHash = transState.getStateHash();
    }
}
