package confidential.statemanagement.privatestate.sender;

import vss.commitment.Commitment;
import vss.secretsharing.Share;

import java.util.LinkedList;

public interface StateSeparationListener {
    void onSeparation(byte[] commonState, LinkedList<Share> shares, LinkedList<Commitment> commitments);
}