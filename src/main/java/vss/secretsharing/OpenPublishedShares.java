package vss.secretsharing;

import vss.commitment.Commitment;
import vss.commitment.CommitmentUtils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Stores shares of corresponding confidential data
 *
 * @author Robin
 */
public class OpenPublishedShares implements Externalizable {
    private Share[] shares;
    private Commitment commitments;
    private byte[] sharedData;

    public OpenPublishedShares() {}

    public OpenPublishedShares(Share[] shares, Commitment commitments, byte[] sharedData) {
        this.shares = shares;
        this.commitments = commitments;
        this.sharedData = sharedData;
    }

    public byte[] getSharedData() {
        return sharedData;
    }

    public Commitment getCommitments() {
        return commitments;
    }

    public Share[] getShares() {
        return shares;
    }

    public Share getShareOf(BigInteger shareholder) {
        for (Share share : shares) {
            if (share.getShareholder().equals(shareholder))
                return share;
        }
        return null;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        CommitmentUtils.getInstance().writeCommitment(commitments, out);
        out.writeInt(sharedData == null ? -1 : sharedData.length);
        if (sharedData != null)
            out.write(sharedData);
        out.writeInt(shares == null ? -1 : shares.length);
        if (shares != null) {
            for (Share share : shares)
                share.writeExternal(out);
        }
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        commitments = CommitmentUtils.getInstance().readCommitment(in);
        int len = in.readInt();
        if (len != -1) {
            sharedData = new byte[len];
            in.readFully(sharedData);
        }
        len = in.readInt();
        if (len != -1) {
            shares = new Share[len];
            Share share;
            for (int i = 0; i < len; i++) {
                share = new Share();
                share.readExternal(in);
                shares[i] = share;
            }
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(String.format("Commitments: %s\nShared data: %s", commitments,
                Arrays.toString(sharedData)));
        sb.append("\nShare:");
        for (Share share : shares) {
            sb.append("\n\t");
            sb.append(share);
        }

        return sb.toString();
    }
}
