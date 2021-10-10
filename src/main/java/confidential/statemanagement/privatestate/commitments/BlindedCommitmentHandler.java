package confidential.statemanagement.privatestate.commitments;

import vss.commitment.Commitment;

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;

public interface BlindedCommitmentHandler {
    void handleNewCommitments(int from, Commitment[] commitments, byte[] commitmentsHash);
    boolean prepareCommitments();
    Map<BigInteger, Commitment[]> readAllCommitments(Set<BigInteger> shareholders);
}
