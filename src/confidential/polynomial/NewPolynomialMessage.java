package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;

public class NewPolynomialMessage extends PolynomialMessage {
    private int f;
    private BigInteger x;
    private BigInteger y;
    private PolynomialCreationReason reason;

    public NewPolynomialMessage() {}

    public NewPolynomialMessage(int id, int sender, int f, int viewId, int leader, int[] viewMembers,
                                BigInteger x, BigInteger y, PolynomialCreationReason reason) {
        super(id, sender, viewId, leader, viewMembers);
        this.f = f;
        this.x = x;
        this.y = y;
        this.reason = reason;
    }

    public int getF() {
        return f;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    public PolynomialCreationReason getReason() {
        return reason;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        super.writeExternal(out);
        out.writeInt(f);
        byte[] b = x.toByteArray();
        out.writeInt(b.length);
        out.write(b);

        b = y.toByteArray();
        out.writeInt(b.length);
        out.write(b);

        out.write((byte)reason.ordinal());
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        super.readExternal(in);
        f = in.readInt();
        byte[] b = new byte[in.readInt()];
        in.readFully(b);
        x = new BigInteger(b);

        b = new byte[in.readInt()];
        in.readFully(b);
        y = new BigInteger(b);
        reason = PolynomialCreationReason.getReason(in.read());
    }
}
