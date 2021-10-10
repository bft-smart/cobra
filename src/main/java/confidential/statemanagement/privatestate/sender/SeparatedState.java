package confidential.statemanagement.privatestate.sender;

import vss.commitment.Commitment;
import vss.secretsharing.Share;

import java.util.LinkedList;

public class SeparatedState {
    private final byte[] commonState;
    private final LinkedList<Share> shares;
    private final LinkedList<Commitment> commitments;

    public SeparatedState(byte[] commonState, LinkedList<Share> shares, LinkedList<Commitment> commitments) {
        this.commonState = commonState;
        this.shares = shares;
        this.commitments = commitments;
    }

    public byte[] getCommonState() {
        return commonState;
    }

    public LinkedList<Share> getShares() {
        return shares;
    }

    public LinkedList<Commitment> getCommitments() {
        return commitments;
    }
}
