package vss.secretsharing;

import vss.commitment.Commitment;
import vss.commitment.CommitmentUtils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;
import java.util.Objects;

/**
 * Stores share, commitments, and encrypted confidential data.
 * This class is used by the shareholders to store its shares.
 *
 * @author Robin
 */
public class VerifiableShare implements Externalizable {
    private Share share;
    private Commitment commitments;
    private byte[] sharedData;

    public VerifiableShare() {}

    public VerifiableShare(Share share, Commitment commitments, byte[] sharedData) {
        this.share = share;
        this.commitments = commitments;
        this.sharedData = sharedData;
    }

    public Share getShare() {
        return share;
    }

    public Commitment getCommitments() {
        return commitments;
    }

    public byte[] getSharedData() {
        return sharedData;
    }

    public void setShare(Share share) {
        this.share = share;
    }

    public void setCommitments(Commitment commitments) {
        this.commitments = commitments;
    }

    public void setSharedData(byte[] sharedData) {
        this.sharedData = sharedData;
    }

    @Override
    public String toString() {
        return String.format("(\n%s\n%s\n%s\n)", share.toString(), commitments.toString(), Arrays.toString(sharedData));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerifiableShare that = (VerifiableShare) o;
        return Objects.equals(share, that.share) &&
                Objects.equals(commitments, that.commitments) &&
                Arrays.equals(sharedData, that.sharedData);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(share, commitments);
        result = 31 * result + Arrays.hashCode(sharedData);
        return result;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        share.writeExternal(out);
        CommitmentUtils.getInstance().writeCommitment(commitments, out);
        out.writeInt(sharedData == null ? -1 : sharedData.length);
        if (sharedData != null)
            out.write(sharedData);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        share = new Share();
        share.readExternal(in);

        commitments = CommitmentUtils.getInstance().readCommitment(in);
        int len = in.readInt();
        if (len != -1) {
            sharedData = new byte[len];
            in.readFully(sharedData);
        }
    }
}
