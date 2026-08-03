package confidential.interServersCommunication;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;

public class InternalMessage implements Externalizable {
    private int sender;
    private byte communicationTag;
    private byte[] message;

    public InternalMessage() {}

    public InternalMessage(int sender, byte communicationTag, byte[] message) {
        this.sender = sender;
        this.communicationTag = communicationTag;
        this.message = message;
    }

    public int getSender() {
        return sender;
    }

    public byte getCommunicationTag() {
        return communicationTag;
    }

    public byte[] getMessage() {
        return message;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(sender);
        out.write(communicationTag);
        out.writeInt(message == null ? -1 : message.length);
        if (message != null)
            out.write(message);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        sender = in.readInt();
        communicationTag = (byte) in.read();
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
                ", tag=" + communicationTag +
                ", message=" + Arrays.toString(message) +
                '}';
    }
}
