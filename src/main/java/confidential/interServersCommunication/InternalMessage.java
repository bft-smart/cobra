package confidential.interServersCommunication;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;

public class InternalMessage implements Externalizable {
    private int sender;
    private CommunicationTag tag;
    private byte[] message;

    public InternalMessage() {}

    public InternalMessage(int sender, CommunicationTag tag, byte[] message) {
        this.sender = sender;
        this.tag = tag;
        this.message = message;
    }

    public int getSender() {
        return sender;
    }

    public CommunicationTag getTag() {
        return tag;
    }

    public byte[] getMessage() {
        return message;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(sender);
        out.write(tag.ordinal());
        out.writeInt(message == null ? -1 : message.length);
        if (message != null)
            out.write(message);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        sender = in.readInt();
        tag = CommunicationTag.getTag(in.read());
        int size = in.readInt();
        if (size != -1) {
            message = new byte[size];
            in.readFully(message);
        }
    }

    @Override
    public String toString() {
        return "InternalMessage{" +
                "sender=" + sender +
                ", tag=" + tag +
                ", message=" + Arrays.toString(message) +
                '}';
    }
}
