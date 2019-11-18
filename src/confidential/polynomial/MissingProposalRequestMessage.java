package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class MissingProposalRequestMessage extends PolynomialMessage {
    private byte[] missingProposals;

    public MissingProposalRequestMessage() {}

    public MissingProposalRequestMessage(int id, int sender, byte[] missingProposals) {
        super(id, sender);
        this.missingProposals = missingProposals;
    }

    public byte[] getMissingProposalCryptographicHash() {
        return missingProposals;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(missingProposals.length);
        out.write(missingProposals);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        missingProposals = new byte[in.readInt()];
        in.readFully(missingProposals);
    }
}
