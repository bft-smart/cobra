package vss.commitment;

import java.io.Externalizable;

/**
 * @author Robin
 */
public interface Commitment extends Externalizable {

    /**
     * Returns the type of commitment
     * @return Type
     */
    CommitmentType getCommitmentType();

    /**
     * Commitments of the same secret will have same hash
     * @return hash
     */
    int consistentHash();

    /**
     * Checks is this commitment and commitment are of the same secret
     * @param commitment Other commitment
     * @return True if both commitments are of the same secret; false otherwise
     */
    boolean isOfSameSecret(Commitment commitment);
}
