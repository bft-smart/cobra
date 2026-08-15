package vss.commitment.constant.ped;

import vss.commitment.constant.ShareKZGCommitment;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;

public class SharePedKZGCommitment extends ShareKZGCommitment {
	private byte[] blindingShare;

	public SharePedKZGCommitment() {}

	public SharePedKZGCommitment(byte[] commitment, byte[] witness, byte[] blindingShare) {
		super(commitment, witness);
		if (blindingShare == null) {
			throw new IllegalArgumentException("Blinding share is null!");
		}
		this.blindingShare = blindingShare;
	}

	public byte[] getBlindingShare() {
		return blindingShare;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		if (!super.equals(o)) return false;

		SharePedKZGCommitment that = (SharePedKZGCommitment) o;

		return Arrays.equals(blindingShare, that.blindingShare);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + Arrays.hashCode(blindingShare);
		return result;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(blindingShare.length);
		out.write(blindingShare);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		super.readExternal(in);
		int blindingShareLength = in.readInt();
		blindingShare = new byte[blindingShareLength];
		in.readFully(blindingShare);
	}
}
