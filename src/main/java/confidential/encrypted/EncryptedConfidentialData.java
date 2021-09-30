package confidential.encrypted;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;

public class EncryptedConfidentialData implements Externalizable {
    private EncryptedVerifiableShare share;

    public EncryptedConfidentialData() {}

    public EncryptedConfidentialData(EncryptedVerifiableShare share) {
        this.share = share;
    }

    public EncryptedVerifiableShare getShare() {
        return share;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        share.writeExternal(out);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        share = new EncryptedVerifiableShare();
        share.readExternal(in);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedConfidentialData that = (EncryptedConfidentialData) o;
        return Arrays.equals(share.getSharedData(), that.share.getSharedData())
                && share.getCommitments().isOfSameSecret(that.share.getCommitments());
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(share.getSharedData());
        result = 31 * result + share.getCommitments().consistentHash();
        return result;
    }
}
