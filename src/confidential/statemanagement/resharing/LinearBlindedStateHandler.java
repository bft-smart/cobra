package confidential.statemanagement.resharing;

import bftsmart.reconfiguration.ServerViewController;
import confidential.polynomial.PolynomialCreationContext;
import confidential.server.ServerConfidentialityScheme;
import confidential.statemanagement.ReconstructionCompleted;
import vss.Utils;
import vss.commitment.Commitment;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class LinearBlindedStateHandler extends BlindedStateHandler {
    private final Map<Integer, Integer> commitments;
    private ObjectInput commitmentsStream;
    private byte[] selectedCommitments;
    private int selectedCommitmentHash;

    public LinearBlindedStateHandler(ServerViewController svController, PolynomialCreationContext context,
                                     VerifiableShare refreshPoint, ServerConfidentialityScheme confidentialityScheme,
                                     int stateSenderReplica, int serverPort, ReconstructionCompleted reconstructionCompleted) {
        super(svController, context, refreshPoint, confidentialityScheme, stateSenderReplica, serverPort, reconstructionCompleted);
        this.commitments = new HashMap<>(oldQuorum);
    }

    @Override
    protected void handleNewCommitments(int from, byte[] serializedCommitments, byte[] commitmentsHash) {
        int commitmentsHashCode = Arrays.hashCode(commitmentsHash);
        if (from == stateSenderReplica) {
            selectedCommitments = serializedCommitments;
            selectedCommitmentHash = commitmentsHashCode;
            logger.debug("Replica {} sent me commitments of {} bytes", from, serializedCommitments.length);
        } else {
            logger.debug("Replica {} sent me hash of commitments", from);
        }

        commitments.merge(commitmentsHashCode, 1, Integer::sum);
    }

    @Override
    protected boolean prepareCommitments() {
        if (commitmentsStream != null)
            return true;
        try {
            if (haveCorrectState(selectedCommitments, commitments, selectedCommitmentHash)) {
                commitmentsStream = new ObjectInputStream(new ByteArrayInputStream(selectedCommitments));
                return true;
            } else {
                logger.info("I don't have enough same commitments");
                return false;
            }
        } catch (IOException e) {
            logger.error("Failed to prepare commitments");
            return false;
        }
    }

    @Override
    protected Map<BigInteger, Commitment> readNextCommitment() throws IOException, ClassNotFoundException {
        Commitment commitment = Utils.readCommitment(commitmentsStream);
        Map<BigInteger, Commitment> result = new HashMap<>(stillValidSenders.size());
        for (Integer sender : stillValidSenders) {
            result.put(confidentialityScheme.getShareholder(sender), commitment);
        }
        return result;
    }
}
