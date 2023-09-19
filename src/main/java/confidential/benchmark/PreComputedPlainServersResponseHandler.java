package confidential.benchmark;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.ServiceResponse;
import confidential.client.ServersResponseHandler;
import vss.secretsharing.Share;

import java.math.BigInteger;

/**
 * @author Robin
 */
public class PreComputedPlainServersResponseHandler extends ServersResponseHandler {
    private boolean preComputed;

    public PreComputedPlainServersResponseHandler() {}

    public void setPreComputed(boolean preComputed) {
        this.preComputed = preComputed;
    }

    @Override
    public ServiceResponse extractResponse(TOMMessage[] replies, int sameContent, int lastReceived) {
        if (preComputed)
            return new ServiceResponse(replies[lastReceived].getCommonContent());

		return super.extractResponse(replies, sameContent, lastReceived);
    }

	@Override
	public ServiceResponse extractHashedResponse(TOMMessage[] replies, TOMMessage fullReply, byte[] fullReplyHash,
												 int sameContent) {
		if (preComputed)
			return new ServiceResponse(fullReply.getCommonContent());
		return super.extractHashedResponse(replies, fullReply, fullReplyHash, sameContent);
	}

	@Override
	protected Share reconstructShare(BigInteger shareholder, byte[] serializedShare) {
		return new Share(shareholder, new BigInteger(serializedShare));
	}
}
