package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class VoteMessage extends PolynomialMessage {
    private byte[][] invalidProposals;

    public VoteMessage() {}

    public VoteMessage(int id, int sender, byte[][] invalidProposals) {
        super(id, sender);
        this.invalidProposals = invalidProposals;
    }

    public byte[][] getInvalidProposals() {
        return invalidProposals;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(invalidProposals.length);
        if (invalidProposals.length > 0)
            out.writeInt(invalidProposals[0].length);
        for (byte[] invalidProposal : invalidProposals) {
            out.write(invalidProposal);
        }
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        int len = in.readInt();
        invalidProposals = new byte[len][];
        if (len > 0) {
            len = in.readInt();
            for (int i = 0; i < invalidProposals.length; i++) {
                byte[] b = new byte[len];
                in.readFully(b);
                invalidProposals[i] = b;
            }
        }
    }
}
