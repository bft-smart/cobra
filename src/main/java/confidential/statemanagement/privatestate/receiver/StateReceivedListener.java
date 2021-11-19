package confidential.statemanagement.privatestate.receiver;

import vss.secretsharing.VerifiableShare;

import java.util.LinkedList;

/**
 * @author robin
 */
public interface StateReceivedListener {
	void onStateReceived(byte[] commonState, LinkedList<VerifiableShare> shares);
}
