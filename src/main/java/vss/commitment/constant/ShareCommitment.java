package vss.commitment.constant;

import vss.commitment.Commitment;
import vss.commitment.CommitmentType;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;

/**
 * @author Robin
 */
public class ShareCommitment implements Commitment {
    private byte[] commitment;
    private byte[] witness;

    public ShareCommitment() {}

    public ShareCommitment(byte[] commitment, byte[] witness) {
        if (commitment == null) {
            throw new IllegalArgumentException("Commitment is null!");
        }
        if (witness == null) {
            throw new IllegalArgumentException("Witness is null!");
        }
        this.commitment = commitment;
        this.witness = witness;
    }

    public byte[] getWitness() {
        return witness;
    }

    public byte[] getCommitment() {
        return commitment;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ShareCommitment that = (ShareCommitment) o;
        return Arrays.equals(commitment, that.commitment) &&
                Arrays.equals(witness, that.witness);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(commitment);
        result = 31 * result + Arrays.hashCode(witness);
        return result;
    }

    @Override
    public CommitmentType getCommitmentType() {
        return CommitmentType.SHARE_COMMITMENT;
    }

    @Override
    public int consistentHash() {
        return Arrays.hashCode(commitment);
    }

    @Override
    public boolean isOfSameSecret(Commitment commitment) {
        if (commitment instanceof ShareCommitment)
            return Arrays.equals(this.commitment, ((ShareCommitment)commitment).commitment);
        else if (commitment instanceof ConstantCommitment)
            return Arrays.equals(this.commitment, ((ConstantCommitment)commitment).getCommitment());
        return false;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(commitment.length);
        out.write(commitment);

        out.writeInt(witness.length);
        out.write(witness);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        commitment = new byte[in.readInt()];
        in.readFully(commitment);

        witness = new byte[in.readInt()];
        in.readFully(witness);
    }

    @Override
    public String toString() {
        return String.format("[commitment: %s,\nwitness: %s]",
                Arrays.toString(commitment), Arrays.toString(witness));
    }
}
