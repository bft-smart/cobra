package confidential.polynomial;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

public class PolynomialCreationContext implements Externalizable {
    private int id;
    private PolynomialContext[] contexts;
    private int leader;
    private PolynomialCreationReason reason;

    public PolynomialCreationContext() {}

    public PolynomialCreationContext(int id, int leader, PolynomialCreationReason reason, PolynomialContext... contexts) {
        this.id = id;
        this.contexts = contexts;
        this.leader = leader;
        this.reason = reason;
    }

    public int getId() {
        return id;
    }

    public PolynomialContext[] getContexts() {
        return contexts;
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
        PolynomialCreationContext that = (PolynomialCreationContext) o;
        return id == that.id &&
                leader == that.leader &&
                Arrays.equals(contexts, that.contexts) &&
                reason == that.reason;
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(id, leader, reason);
        result = 31 * result + Arrays.hashCode(contexts);
        return result;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(id);

        if (contexts == null)
            out.writeInt(-1);
        else {
            out.writeInt(contexts.length);
            for (PolynomialContext context : contexts) {
                context.writeExternal(out);
            }
        }

        out.writeInt(leader);
        out.write((byte)reason.ordinal());
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        id = in.readInt();

        int len = in.readInt();
        if (len > -1) {
            contexts = new PolynomialContext[len];
            for (int i = 0; i < len; i++) {
                contexts[i] = new PolynomialContext();
                contexts[i].readExternal(in);
            }
        }

        leader = in.readInt();
        reason = PolynomialCreationReason.getReason(in.read());
    }
}
