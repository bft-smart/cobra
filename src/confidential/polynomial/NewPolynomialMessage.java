package confidential.polynomial;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;

public class NewPolynomialMessage extends PolynomialMessage {
    private int f;
    private BigInteger x;
    private BigInteger y;

    public NewPolynomialMessage() {}

    public NewPolynomialMessage(int sender, int f, BigInteger x, BigInteger y) {
        super(sender);
        this.f = f;
        this.x = x;
        this.y = y;
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
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        super.readExternal(in);
        f = in.readInt();
        byte[] b = new byte[in.readInt()];
        in.readFully(b);
        x = new BigInteger(b);

        b = new byte[in.readInt()];
        in.readFully(b);
        y = new BigInteger(b);
    }
}
