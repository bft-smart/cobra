package confidential.statemanagement.privatestate.commitments;

import confidential.server.ServerConfidentialityScheme;
import vss.commitment.Commitment;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class ConstantCommitmentHandler implements BlindedCommitmentHandler {
    private final Map<Integer, Commitment[]> allCommitments;
    private final int quorum;
    private final ServerConfidentialityScheme confidentialityScheme;

    public ConstantCommitmentHandler(int quorum, ServerConfidentialityScheme confidentialityScheme) {
        allCommitments = new HashMap<>(quorum);
        this.quorum = quorum;
        this.confidentialityScheme = confidentialityScheme;
    }

    @Override
    public void handleNewCommitments(int from, Commitment[] commitments, byte[] commitmentsHash) {
        allCommitments.put(from, commitments);
    }

    @Override
    public boolean prepareCommitments() {
        return allCommitments.size() >= quorum;
    }

    @Override
    public Map<BigInteger, Commitment[]> readAllCommitments(Set<BigInteger> shareholders) {
        Map<BigInteger, Commitment[]> result = new HashMap<>(shareholders.size());
        for (BigInteger shareholder : shareholders) {
            int server = confidentialityScheme.getProcess(shareholder);
            result.put(shareholder, allCommitments.get(server));
        }
        return result;
    }

}
