package confidential.client;

import vss.secretsharing.Share;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author Robin
 */
public class PlainServersResponseHandler extends ServersResponseHandler {

	public PlainServersResponseHandler() {}

	@Override
	protected Share reconstructShare(BigInteger shareholder, byte[] serializedShare) {
		return new Share(shareholder, new BigInteger(serializedShare));
	}
}
