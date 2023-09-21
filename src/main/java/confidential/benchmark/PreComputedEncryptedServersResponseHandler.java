package confidential.benchmark;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.ServiceResponse;
import confidential.ExtractedResponse;
import confidential.client.ServersResponseHandler;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;

import java.math.BigInteger;

/**
 * @author Robin
 */
public class PreComputedEncryptedServersResponseHandler extends ServersResponseHandler {
    private final int clientId;
    private boolean preComputed;

    public PreComputedEncryptedServersResponseHandler(int clientId) {
        this.clientId = clientId;
    }

    public void setPreComputed(boolean preComputed) {
        this.preComputed = preComputed;
    }

    @Override
    public ServiceResponse extractResponse(TOMMessage[] replies, int sameContent, int lastReceived) {
        if (preComputed)
            return new ExtractedResponse(null, null);

		return super.extractResponse(replies, sameContent, lastReceived);
    }

	@Override
	public ServiceResponse extractHashedResponse(TOMMessage[] replies, TOMMessage fullReply, byte[] fullReplyHash, int sameContent) {
		if (preComputed)
			return new ExtractedResponse(null, null);
		return super.extractHashedResponse(replies, fullReply, fullReplyHash, sameContent);
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
