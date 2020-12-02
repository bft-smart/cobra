package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class ProposalMessage extends PolynomialMessage {
    private Proposal[] proposals;
    private byte[] cryptographicHash;
    private byte[] signature;

    public ProposalMessage() {}

    public ProposalMessage(int id, int sender, Proposal... proposals) {
        super(id, sender);
        this.proposals = proposals;
    }

    public Proposal[] getProposals() {
        return proposals;
    }

    public byte[] getCryptographicHash() {
        return cryptographicHash;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setCryptographicHash(byte[] cryptographicHash) {
        this.cryptographicHash = cryptographicHash;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        if (proposals == null)
            out.writeInt(-1);
        else {
            out.writeInt(proposals.length);
            for (Proposal proposal : proposals) {
                proposal.writeExternal(out);
            }
        }

        out.writeInt(signature == null ? -1 : signature.length);
        if (signature != null)
            out.write(signature);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        int size = in.readInt();
        if (size > -1) {
            proposals = new Proposal[size];
            for (int i = 0; i < size; i++) {
                proposals[i] = new Proposal();
                proposals[i].readExternal(in);
            }
        }

        size = in.readInt();
        if (size > -1) {
            signature = new byte[size];
            in.readFully(signature);
        }
    }
}
