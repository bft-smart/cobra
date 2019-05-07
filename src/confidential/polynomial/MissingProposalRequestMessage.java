package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class MissingProposalRequestMessage extends PolynomialMessage {
    private byte[][] missingProposals;

    public MissingProposalRequestMessage() {}

    public MissingProposalRequestMessage(int id, int sender, byte[][] missingProposals) {
        super(id, sender);
        this.missingProposals = missingProposals;
    }

    public byte[][] getMissingProposals() {
        return missingProposals;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(missingProposals.length);
        out.writeInt(missingProposals[0].length);
        for (byte[] missingProposal : missingProposals) {
            out.write(missingProposal);
        }
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        super.readExternal(in);
        missingProposals = new byte[in.readInt()][];
        int len = in.readInt();
        for (int i = 0; i < missingProposals.length; i++) {
            byte[] b = new byte[len];
            in.readInt();
            missingProposals[i] = b;
        }
    }
}
