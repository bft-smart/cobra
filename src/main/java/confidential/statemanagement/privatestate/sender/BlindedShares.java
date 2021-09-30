package confidential.statemanagement.privatestate.sender;

import vss.commitment.Commitment;

public class BlindedShares {
    private final byte[][] share;
    private final Commitment[] commitment;

    public BlindedShares(byte[][] share, Commitment[] commitment) {
        this.share = share;
        this.commitment = commitment;
    }

    public byte[][] getShare() {
        return share;
    }

    public Commitment[] getCommitment() {
        return commitment;
    }
}
