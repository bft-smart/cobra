package confidential.server;

import confidential.ConfidentialData;
import confidential.MessageType;

import java.io.*;

public final class Request {
    private MessageType type;
    private byte[] plainData;
    private ConfidentialData[] shares;

    public Request(MessageType type, byte[] plainData, ConfidentialData... shares) {
        this.type = type;
        this.plainData = plainData;
        this.shares = shares;
    }

    public MessageType getType() {
        return type;
    }

    public byte[] getPlainData() {
        return plainData;
    }

    public ConfidentialData[] getShares() {
        return shares;
    }

    public void setShares(ConfidentialData[] shares) {
        this.shares = shares;
    }

    public byte[] serialize() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.write((byte)type.ordinal());
            out.writeInt(plainData == null ? -1 : plainData.length);
            if (plainData != null)
                out.write(plainData);
            out.writeInt(shares == null ? -1 : shares.length);
            if (shares != null) {
                for (ConfidentialData share : shares)
                    share.writeExternal(out);
            }
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Request deserialize(byte[] serializedData) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedData);
             ObjectInput in = new ObjectInputStream(bis)) {
            MessageType type = MessageType.getMessageType(in.read());
            int len = in.readInt();
            byte[] plainData = len == -1 ? null : new byte[len];
            if (len != -1)
                in.readFully(plainData);

            len = in.readInt();
            ConfidentialData[] shares = len == -1 ? null : new ConfidentialData[len];
            if (len != -1) {
                ConfidentialData share;
                for (int i = 0; i < shares.length; i++) {
                    share = new ConfidentialData();
                    share.readExternal(in);
                    shares[i] = share;
                }
            }
            return new Request(type, plainData, shares);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }
}
