package confidential.polynomial;

import vss.commitment.Commitments;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class ProposalMessage extends PolynomialMessage {
    private byte[][] encryptedPoints;
    private Commitments commitments;
    private byte[] cryptographicHash;

    public ProposalMessage() {}

    public ProposalMessage(int id, int sender, int viewId, int leader, int[] viewMembers, byte[][] encryptedPoints,
                           Commitments commitments) {
        super(id, sender, viewId, leader, viewMembers);
        this.encryptedPoints = encryptedPoints;
        this.commitments = commitments;
    }

    public byte[][] getEncryptedPoints() {
        return encryptedPoints;
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
        out.writeInt(encryptedPoints.length);
        for (byte[] v : encryptedPoints) {
            out.writeInt(v.length);
            out.write(v);
        }

        commitments.writeExternal(out);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        int len = in.readInt();
        encryptedPoints = new byte[len][];
        for (int i = 0; i < encryptedPoints.length; i++) {
            len = in.readInt();
            byte[] b = new byte[len];
            in.readFully(b);
            encryptedPoints[i] = b;
        }

        commitments = new Commitments();
        commitments.readExternal(in);
    }
}
