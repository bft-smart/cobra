package confidential.polynomial;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class PolynomialMessage implements Externalizable {
    private int sender;

    public PolynomialMessage() {}

    public PolynomialMessage(int sender) {
        this.sender = sender;
    }

    public int getSender() {
        return sender;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(sender);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        sender = in.readInt();
    }
}
