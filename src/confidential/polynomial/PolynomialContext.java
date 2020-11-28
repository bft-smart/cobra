package confidential.polynomial;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

public class PolynomialContext implements Externalizable {
    private int f;
    private BigInteger x;
    private BigInteger y;
    private int[] members;

    public PolynomialContext() {}

    public PolynomialContext(int f, BigInteger x, BigInteger y, int[] members) {
        this.f = f;
        this.x = x;
        this.y = y;
        this.members = members;
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

    public int[] getMembers() {
        return members;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PolynomialContext that = (PolynomialContext) o;
        return f == that.f &&
                Objects.equals(x, that.x) &&
                Objects.equals(y, that.y) &&
                Arrays.equals(members, that.members);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(f, x, y);
        result = 31 * result + Arrays.hashCode(members);
        return result;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(f);

        byte[] b;
        if (x == null)
            out.writeInt(-1);
        else {
            b = x.toByteArray();
            out.writeInt(b.length);
            out.write(b);
        }

        if (y == null)
            out.writeInt(-1);
        else {
            b = y.toByteArray();
            out.writeInt(b.length);
            out.write(b);
        }
        if (members == null)
            out.writeInt(-1);
        else {
            out.writeInt(members.length);
            for (int m : members)
                out.writeInt(m);
        }
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        f = in.readInt();

        byte[] b;
        int len = in.readInt();
        if (len > -1) {
            b = new byte[len];
            in.readFully(b);
            x = new BigInteger(b);
        }

        len = in.readInt();
        if (len > -1) {
            b = new byte[len];
            in.readFully(b);
            y = new BigInteger(b);
        }

        len = in.readInt();
        if (len > -1) {
            members = new int[len];
            for (int i = 0; i < members.length; i++)
                members[i] = in.readInt();
        }
    }
}
