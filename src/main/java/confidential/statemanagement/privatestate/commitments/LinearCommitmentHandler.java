package confidential.statemanagement.privatestate.commitments;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;

import java.math.BigInteger;
import java.util.*;

public class LinearCommitmentHandler implements BlindedCommitmentHandler {
    private final Logger logger = LoggerFactory.getLogger("state_transfer");
    private final int f;
    private final Map<Integer, Integer> commitmentsHashCode;
    private final int stateSenderReplica;
    private Commitment[] selectedCommitments;
    private int selectedCommitmentHash;
    private int index;

    public LinearCommitmentHandler(int f, int quorum, int stateSenderReplica) {
        this.f = f;
        this.commitmentsHashCode = new HashMap<>(quorum);
        this.stateSenderReplica = stateSenderReplica;
    }

    @Override
    public void handleNewCommitments(int from, Commitment[] commitments, byte[] commitmentsHash) {
        int commitmentsHashCode = Arrays.hashCode(commitmentsHash);
        if (from == stateSenderReplica) {
            selectedCommitments = commitments;
            selectedCommitmentHash = commitmentsHashCode;
            logger.debug("Replica {} sent me {} commitments", from, commitments.length);
        } else {
            logger.debug("Replica {} sent me hash of commitments", from);
        }

        this.commitmentsHashCode.merge(commitmentsHashCode, 1, Integer::sum);
    }

    @Override
    public boolean prepareCommitments() {
        if (selectedCommitments == null)
            return false;
        if (haveCorrectState(commitmentsHashCode, selectedCommitmentHash)) {
            return true;
        } else {
            logger.info("I don't have enough same commitments");
            return false;
        }
    }

    @Override
    public Map<BigInteger, Commitment[]> readAllCommitments(Set<BigInteger> shareholders) {
        Map<BigInteger, Commitment[]> result = new HashMap<>(shareholders.size());
        for (BigInteger shareholder : shareholders) {
            result.put(shareholder, selectedCommitments);
        }
        return result;
    }

    private boolean haveCorrectState(Map<Integer, Integer> states,
                                     int selectedStateHash) {
        Optional<Map.Entry<Integer, Integer>> max = states.entrySet().stream()
                .max(Comparator.comparingInt(Map.Entry::getValue));
        if (!max.isPresent()) {
            logger.info("I don't have correct common state");
            return false;
        }
        Map.Entry<Integer, Integer> entry = max.get();
        if (entry.getValue() <= f) {
            logger.info("I don't have correct common state");
            return false;
        }

        return selectedStateHash == entry.getKey();
    }
}
