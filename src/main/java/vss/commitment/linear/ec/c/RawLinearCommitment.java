package vss.commitment.linear.ec.c;

import vss.commitment.Commitment;
import vss.commitment.CommitmentType;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.Objects;

public class RawLinearCommitment implements Commitment {
	private byte[][] commitments;

	public RawLinearCommitment() {}

	public RawLinearCommitment(byte[][] commitments) {
		this.commitments = commitments;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof RawLinearCommitment)) return false;
		RawLinearCommitment that = (RawLinearCommitment) o;
		return Objects.deepEquals(commitments, that.commitments);
	}

	@Override
	public int hashCode() {
		return Arrays.deepHashCode(commitments);
	}

	@Override
	public CommitmentType getCommitmentType() {
		return CommitmentType.ELLIPTIC_CURVE;
	}

	@Override
	public int consistentHash() {
		return hashCode();
	}

	@Override
	public boolean isOfSameSecret(Commitment commitment) {
		return equals(commitment);
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(commitments == null ? -1 : commitments.length);
		if (commitments != null) {
			for (byte[] commitment : commitments) {
				out.writeInt(commitment == null ? -1 : commitment.length);
				out.write(commitment);
			}
		}
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		int size = in.readInt();
		if (size != -1) {
			commitments = new byte[size][];
			for (int i = 0; i < size; i++) {
				int len = in.readInt();
				if (len != -1) {
					commitments[i] = new byte[len];
					in.readFully(commitments[i]);
				}
			}
		}
	}

	public byte[][] getCommitments() {
		return commitments;
	}
}
