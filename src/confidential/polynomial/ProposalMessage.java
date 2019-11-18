package confidential.polynomial;

import vss.Utils;
import vss.commitment.Commitment;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;

public class ProposalMessage extends PolynomialMessage {
    private BigInteger point;
    private Commitment commitments;
    private byte[] cryptographicHash;

    public ProposalMessage() {}

    public ProposalMessage(int id, int sender, BigInteger point, Commitment commitments) {
        super(id, sender);
        this.point = point;
        this.commitments = commitments;
    }

    public BigInteger getPoint() {
        return point;
    }

    public Commitment getCommitments() {
        return commitments;
    }

    public byte[] getCryptographicHash() {
        return cryptographicHash;
    }

    public void setCryptographicHash(byte[] cryptographicHash) {
        this.cryptographicHash = cryptographicHash;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        byte[] b = point.toByteArray();
        out.writeInt(b.length);
        out.write(b);

        Utils.writeCommitment(commitments, out);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        byte[] b = new byte[in.readInt()];
        in.readFully(b);
        point = new BigInteger(b);

        commitments = Utils.readCommitment(in);
    }
}
