package confidential.encrypted;

import vss.commitment.Commitment;

import java.util.Map;

/**
 * Stores encrypted shares of a private data
 *
 * @author robin
 */
public class EncryptedPublishedShares {
	//private Mode mode;
	private final Map<Integer, byte[]> encryptedShares;//<server id, encrypted share>
	private final Commitment commitment;
	private final byte[] sharedData;

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
}
