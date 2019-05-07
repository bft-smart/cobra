package confidential.polynomial;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

public class PolynomialContext implements Externalizable {
    private int id;
    private int f;
    private BigInteger x;
    private BigInteger y;
    private int[] members;
    private int leader;
    private PolynomialCreationReason reason;

    public PolynomialContext() {}

    public PolynomialContext(int id, int f, BigInteger x, BigInteger y, int[] members, int leader, PolynomialCreationReason reason) {
        this.id = id;
        this.f = f;
        this.x = x;
        this.y = y;
        this.members = members;
        this.leader = leader;
        this.reason = reason;
    }

    public int getId() {
        return id;
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

    public int getLeader() {
        return leader;
    }

    public PolynomialCreationReason getReason() {
        return reason;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PolynomialContext that = (PolynomialContext) o;
        return id == that.id &&
                f == that.f &&
                leader == that.leader &&
                x.equals(that.x) &&
                y.equals(that.y) &&
                Arrays.equals(members, that.members) &&
                reason == that.reason;
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(id, f, x, y, leader, reason);
        result = 31 * result + Arrays.hashCode(members);
        return result;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(id);
        out.writeInt(f);

        byte[] b = x.toByteArray();
        out.writeInt(b.length);
        out.write(b);

        b = y.toByteArray();
        out.writeInt(b.length);
        out.write(b);

        out.writeInt(members.length);
        for (int m : members)
            out.writeInt(m);

        out.writeInt(leader);
        out.write((byte)reason.ordinal());
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        id = in.readInt();
        f = in.readInt();

        byte[] b = new byte[in.readInt()];
        in.readFully(b);
        x = new BigInteger(b);

        b = new byte[in.readInt()];
        in.readFully(b);
        y = new BigInteger(b);

        members = new int[in.readInt()];
        for (int i = 0; i < members.length; i++)
            members[i] = in.readInt();

        leader = in.readInt();
        reason = PolynomialCreationReason.getReason(in.read());
    }
}
