package confidential.encrypted;

import vss.Utils;
import vss.commitment.Commitment;
import vss.facade.Mode;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Stores encrypted shares of a private data
 *
 * @author robin
 */
public class EncryptedPublishedShares implements Externalizable {
	private Map<Integer, byte[]> encryptedShares;//<server id, encrypted share>
	private Commitment commitment;
	private byte[] sharedData;

	public EncryptedPublishedShares() {}

	public EncryptedPublishedShares(Map<Integer, byte[]> encryptedShares,
									Commitment commitment, byte[] sharedData) {
		this.encryptedShares = encryptedShares;
		this.commitment = commitment;
		this.sharedData = sharedData;
	}

	public Map<Integer, byte[]> getEncryptedShares() {
		return encryptedShares;
	}

	public Commitment getCommitment() {
		return commitment;
	}

	public byte[] getSharedData() {
		return sharedData;
	}

	public byte[] getShareOf(int server) {
		return encryptedShares.get(server);
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(encryptedShares == null ? -1 : encryptedShares.size());
		if (encryptedShares != null && !encryptedShares.isEmpty()) {
			int[] ids = new int[encryptedShares.size()];
			int index = 0;
			for (int key : encryptedShares.keySet()) {
				ids[index++] = key;
			}
			Arrays.sort(ids);
			byte[] encryptedShare;
			for (int id : ids) {
				out.writeInt(id);
				encryptedShare = encryptedShares.get(id);
				out.writeInt(encryptedShare.length);
				out.write(encryptedShare);
			}
		}
		Utils.writeCommitment(commitment, out);
		out.writeInt(sharedData == null ? -1 : sharedData.length);
		if (sharedData != null)
			out.write(sharedData);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		int len = in.readInt();
		if (len != -1) {
			encryptedShares = new HashMap<>(len);
			byte[] encryptedShare;
			while (len-- > 0) {
				int id = in.readInt();
				encryptedShare = new byte[in.readInt()];
				in.readFully(encryptedShare);
				encryptedShares.put(id, encryptedShare);
			}
		}
		commitment = Utils.readCommitment(in);
		len = in.readInt();
		if (len != -1) {
			sharedData = new byte[len];
			in.readFully(sharedData);
		}
	}
}
