package confidential;

import vss.secretsharing.VerifiableShare;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.LinkedList;
import java.util.List;

public class ConfidentialData implements Externalizable {
    private VerifiableShare share;
    private List<VerifiableShare> publicShares;

    public ConfidentialData() {}

    public ConfidentialData(VerifiableShare share) {
        this.share = share;
    }

    public void addPublicShare(VerifiableShare share) {
        if (publicShares == null)
            publicShares = new LinkedList<>();
        publicShares.add(share);
    }

    public List<VerifiableShare> getPublicShares() {
        return publicShares;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        share.writeExternal(out);
        out.writeInt(publicShares == null ? -1 : publicShares.size());
        if (publicShares != null)
            for (VerifiableShare share : publicShares) {
                share.writeExternal(out);
            }
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        share = new VerifiableShare();
        share.readExternal(in);
        int len = in.readInt();
        if (len != -1) {
            publicShares = new LinkedList<>();
            while (len-- > 0) {
                VerifiableShare share = new VerifiableShare();
                share.readExternal(in);
                publicShares.add(share);
            }
        }
    }
}
