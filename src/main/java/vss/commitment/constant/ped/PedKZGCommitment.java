package vss.commitment.constant.ped;

import vss.commitment.constant.KZGCommitment;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

public class PedKZGCommitment extends KZGCommitment {
	private TreeMap<Integer, byte[]> blindingShares;

	public PedKZGCommitment() {}

	public PedKZGCommitment(byte[] commitment, TreeMap<Integer, byte[]> witnesses, TreeMap<Integer, byte[]> blindingShares) {
		super(commitment, witnesses);
		this.blindingShares = blindingShares;
	}

	public byte[] getBlindingShare(BigInteger shareholder) {
		return blindingShares.get(shareholder.hashCode());
	}

	public byte[] getBlindingShare(int shareholderHash) {
		return blindingShares.get(shareholderHash);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof PedKZGCommitment)) return false;
		if (!super.equals(o)) return false;

		PedKZGCommitment that = (PedKZGCommitment) o;

		return Objects.equals(blindingShares, that.blindingShares);
	}

	@Override
	public int hashCode() {
		return Objects.hash(super.hashCode(), blindingShares);
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(blindingShares.size());
		for (Map.Entry<Integer, byte[]> entry : blindingShares.entrySet()) {
			out.writeInt(entry.getKey());
			byte[] value = entry.getValue();
			out.writeInt(value.length);
			out.write(value);
		}
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException {
		super.readExternal(in);
		int size = in.readInt();
		blindingShares = new TreeMap<>();
		for (int i = 0; i < size; i++) {
			int key = in.readInt();
			int valueLength = in.readInt();
			byte[] value = new byte[valueLength];
			in.readFully(value);
			blindingShares.put(key, value);
		}
	}

	@Override
	public int consistentHash() {
		return Objects.hash(super.consistentHash(), blindingShares);
	}

	public TreeMap<Integer, byte[]> getBlindingShares() {
		return blindingShares;
	}
}
