package vss.commitment.linear;

import vss.commitment.Commitment;
import vss.commitment.CommitmentType;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * This class stores array of commitments
 *
 * @author Robin
 */
public class LinearCommitments implements Commitment, Serializable {
    private BigInteger[] commitments;

    public LinearCommitments() {}

    /**
     * Creates object with array of commitments
     * @param commitments Array of commitments
     */
    public LinearCommitments(BigInteger... commitments) {
        this.commitments = commitments;
    }

    /**
     * Returns array of commitments
     * @return Array of commitments
     */
    public BigInteger[] getCommitments() {
        return commitments;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LinearCommitments that = (LinearCommitments) o;
        return Arrays.equals(commitments, that.commitments);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(commitments);
    }

    @Override
    public String toString() {
        return Arrays.toString(commitments);
    }

    /**
     * Serialized this Commmitment
     * @param out Stream to serialize
     * @throws IOException When fails to serialize
     */
    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(commitments == null ? -1 : commitments.length);
        if (commitments == null)
            return;
        byte[] b;
        for (BigInteger commitment : commitments) {
            b = commitment.toByteArray();
            out.writeInt(b.length);
            out.write(b);
        }
    }

    /**
     * Deserialize content of this object
     * @param in Input stream of content
     * @throws IOException When fails to deserialize
     */
    @Override
    public void readExternal(ObjectInput in) throws IOException {
        int len = in.readInt();
        if (len == -1)
            return;
        commitments = new BigInteger[len];
        byte[] b;
        for (int i = 0; i < len; i++) {
            b = new byte[in.readInt()];
            in.readFully(b);
            commitments[i] = new BigInteger(b);
        }

    }

    @Override
    public CommitmentType getCommitmentType() {
        return CommitmentType.LINEAR;
    }

    @Override
    public int consistentHash() {
        return hashCode();
    }

    @Override
    public boolean isOfSameSecret(Commitment commitment) {
        return equals(commitment);
    }
}
