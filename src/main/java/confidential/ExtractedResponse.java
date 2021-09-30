package confidential;

import vss.facade.SecretSharingException;

import java.io.*;

public class ExtractedResponse {
    private final byte[] plainData;
    private final byte[][] confidentialData;
    private final SecretSharingException throwable;

    public ExtractedResponse(byte[] plainData, byte[][] confidentialData, SecretSharingException throwable) {
        this.plainData = plainData;
        this.confidentialData = confidentialData;
        this.throwable = throwable;
    }

    public ExtractedResponse(byte[] plainData, byte[][] confidentialData) {
        this.plainData = plainData;
        this.confidentialData = confidentialData;
        this.throwable = null;
    }

    public SecretSharingException getThrowable() {
        return throwable;
    }

    public byte[] getPlainData() {
        return plainData;
    }

    public byte[][] getConfidentialData() {
        return confidentialData;
    }

    public byte[] serialize() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeBoolean(throwable != null);
            if (throwable != null)
                out.writeObject(throwable);
            out.writeInt(plainData == null ? -1 : plainData.length);
            if (plainData != null)
                out.write(plainData);

            out.writeInt(confidentialData == null ? -1 : confidentialData.length);
            if (confidentialData != null) {
                for (byte[] c : confidentialData) {
                    out.writeInt(c.length);
                    out.write(c);
                }
            }

            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static ExtractedResponse deserialize(byte[] serializedData) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedData);
             ObjectInput in = new ObjectInputStream(bis)) {
            SecretSharingException throwable = null;
            if (in.readBoolean())
                throwable = (SecretSharingException)in.readObject();
            int len = in.readInt();
            byte[] plainData = len == -1 ? null : new byte[len];
            if (len != -1)
                in.readFully(plainData);

            len = in.readInt();
            byte[][] confidentialData = len == -1 ? null : new byte[len][];
            if (len != -1) {
                byte[] c;
                for (int i = 0; i < confidentialData.length; i++) {
                    c = new byte[in.readInt()];
                    in.readFully(c);
                    confidentialData[i] = c;
                }
            }
            return new ExtractedResponse(plainData, confidentialData, throwable);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }
}
