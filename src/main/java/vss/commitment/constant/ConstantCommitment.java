package vss.commitment.constant;

import vss.commitment.Commitment;
import vss.commitment.CommitmentType;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * @author Robin
 */
public class ConstantCommitment implements Commitment {
    private byte[] commitment;
    private TreeMap<Integer, byte[]> witnesses;

    public ConstantCommitment() {}

    public ConstantCommitment(byte[] commitment, TreeMap<Integer, byte[]> witnesses) {
        if (commitment == null) {
            throw new IllegalArgumentException("Commitment is null!");
        }
        if (witnesses == null) {
            throw new IllegalArgumentException("Witnesses are null!");
        }
        this.commitment = commitment;
        this.witnesses = witnesses;
    }

    public byte[] getCommitment() {
        return commitment;
    }

    public byte[] getWitness(BigInteger shareholder) {
        return witnesses.get(shareholder.hashCode());
    }

    public byte[] getWitness(int shareholderHash) {
        return witnesses.get(shareholderHash);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ConstantCommitment that = (ConstantCommitment) o;
        return Arrays.equals(commitment, that.commitment) &&
                witnesses.equals(that.witnesses);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(witnesses);
        result = 31 * result + Arrays.hashCode(commitment);
        return result;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(commitment.length);
        out.write(commitment);
        out.writeInt(witnesses.size());
        for (Map.Entry<Integer, byte[]> entry : witnesses.entrySet()) {
            out.writeInt(entry.getKey());
            out.writeInt(entry.getValue().length);
            out.write(entry.getValue());
        }
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        commitment = new byte[in.readInt()];
        in.readFully(commitment);
        int len = in.readInt();
        witnesses = new TreeMap<>();
        byte[] b;
        while (len-- > 0) {
            int key = in.readInt();
            b = new byte[in.readInt()];
            in.readFully(b);
            witnesses.put(key, b);
        }
    }

    @Override
    public CommitmentType getCommitmentType() {
        return CommitmentType.CONSTANT;
    }

    @Override
    public int consistentHash() {
        return Arrays.hashCode(commitment);
    }

    @Override
    public boolean isOfSameSecret(Commitment commitment) {
        if (commitment instanceof ShareCommitment)
            return Arrays.equals(this.commitment, ((ShareCommitment)commitment).getCommitment());
        else if (commitment instanceof ConstantCommitment)
            return Arrays.equals(this.commitment, ((ConstantCommitment)commitment).commitment);
        return false;
    }

    public Map<Integer, byte[]> getWitnesses() {
        return witnesses;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[commitment: ");
        sb.append(Arrays.toString(commitment));
        sb.append(",\n");
        sb.append("witnesses:\n");
        for (Map.Entry<Integer, byte[]> entry : witnesses.entrySet()) {
            sb.append("\t");
            sb.append(entry.getKey());
            sb.append(" -> ");
            sb.append(Arrays.toString(entry.getValue()));
            sb.append("\n");
        }
        sb.append("]");
        return sb.toString();
    }
}
