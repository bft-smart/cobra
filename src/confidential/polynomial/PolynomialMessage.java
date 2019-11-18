package confidential.polynomial;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

public class PolynomialMessage implements Externalizable {
    private int id;
    private int sender;

    public PolynomialMessage() {}

    public PolynomialMessage(int id, int sender) {
        this.id = id;
        this.sender = sender;
    }

    public int getId() {
        return id;
    }

    public int getSender() {
        return sender;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(id);
        out.writeInt(sender);

    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        id = in.readInt();
        sender = in.readInt();
    }
}
