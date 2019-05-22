package confidential.polynomial;

import vss.commitment.Commitments;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;

public class ProposalMessage extends PolynomialMessage {
    private BigInteger point;
    private Commitments commitments;
    private byte[] cryptographicHash;

    public ProposalMessage() {}

    public ProposalMessage(int id, int sender, BigInteger point, Commitments commitments) {
        super(id, sender);
        this.point = point;
        this.commitments = commitments;
    }

    public BigInteger getPoint() {
        return point;
    }

    public Commitments getCommitments() {
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

        commitments.writeExternal(out);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        super.readExternal(in);
        byte[] b = new byte[in.readInt()];
        in.readFully(b);
        point = new BigInteger(b);

        commitments = new Commitments();
        commitments.readExternal(in);
    }
}
