package confidential.encrypted;

import vss.commitment.Commitment;
import vss.commitment.CommitmentUtils;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * Stores share, commitments, and encrypted confidential data.
 * This class is used by the shareholders to store its shares.
 *
 * @author Robin
 */
public class EncryptedVerifiableShare implements Externalizable {
    private BigInteger shareholder;
    private byte[] share;
    private Commitment commitments;
    private byte[] sharedData;

    public EncryptedVerifiableShare() {}

    public EncryptedVerifiableShare(BigInteger shareholder, byte[] share, Commitment commitments, byte[] sharedData) {
        this.shareholder = shareholder;
        this.share = share;
        this.commitments = commitments;
        this.sharedData = sharedData;
    }

    public BigInteger getShareholder() {
        return shareholder;
    }

    public byte[] getShare() {
        return share;
    }

    public Commitment getCommitments() {
        return commitments;
    }

    public byte[] getSharedData() {
        return sharedData;
    }

    public void setShare(byte[] share) {
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
        return String.format("(\n%s\n%s\n%s\n)", Arrays.toString(share), commitments.toString(), Arrays.toString(sharedData));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedVerifiableShare that = (EncryptedVerifiableShare) o;
        return Objects.equals(commitments, that.commitments) &&
                Arrays.equals(share, that.share) &&
                Arrays.equals(sharedData, that.sharedData);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(commitments);
        result = 31 * result + Arrays.hashCode(share);
        result = 31 * result + Arrays.hashCode(sharedData);
        return result;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        byte[] shareholderBytes = shareholder.toByteArray();
        out.writeInt(shareholderBytes.length);
        out.write(shareholderBytes);
        out.writeInt(share == null ? -1 : share.length);
        if (share != null)
            out.write(share);
        CommitmentUtils.getInstance().writeCommitment(commitments, out);
        out.writeInt(sharedData == null ? -1 : sharedData.length);
        if (sharedData != null)
            out.write(sharedData);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        int len = in.readInt();
        byte[] shareholderBytes = new byte[len];
        in.readFully(shareholderBytes);
        shareholder = new BigInteger(shareholderBytes);

        len = in.readInt();
        if (len != -1) {
            share = new byte[len];
            in.readFully(share);
        }

        commitments = CommitmentUtils.getInstance().readCommitment(in);
        len = in.readInt();
        if (len != -1) {
            sharedData = new byte[len];
            in.readFully(sharedData);
        }
    }
}
