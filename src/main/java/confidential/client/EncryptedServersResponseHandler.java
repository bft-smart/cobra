package confidential.client;

import vss.facade.SecretSharingException;
import vss.secretsharing.Share;

import java.math.BigInteger;

/**
 * @author Robin
 */
public class EncryptedServersResponseHandler extends ServersResponseHandler {
	private final int clientId;

	public EncryptedServersResponseHandler(int clientId) {
		this.clientId = clientId;
	}

	@Override
	protected Share reconstructShare(BigInteger shareholder, byte[] serializedShare) {
		try {
			return new Share(shareholder, confidentialityScheme.decryptShareFor(clientId, serializedShare));
		} catch (SecretSharingException e) {
			logger.error("Failed to decrypt share of {}", shareholder, e);
			return null;
		}
	}
}
