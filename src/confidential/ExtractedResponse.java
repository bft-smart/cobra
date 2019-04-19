package confidential;

import vss.secretsharing.OpenPublishedShares;

import java.io.*;

public class ExtractedResponse {
    private final byte[] plainData;
    private final OpenPublishedShares[] openShares;

    public ExtractedResponse(byte[] plainData, OpenPublishedShares[] openShares) {
        this.plainData = plainData;
        this.openShares = openShares;
    }

    public byte[] getPlainData() {
        return plainData;
    }

    public OpenPublishedShares[] getOpenShares() {
        return openShares;
    }

    public byte[] serialize() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeInt(plainData == null ? -1 : plainData.length);
            if (plainData != null)
                out.write(plainData);

            out.writeInt(openShares == null ? -1 : openShares.length);
            if (openShares != null) {
                for (OpenPublishedShares openShares : openShares)
                    openShares.writeExternal(out);
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
            int len = in.readInt();
            byte[] plainData = len == -1 ? null : new byte[len];
            if (len != -1)
                in.readFully(plainData);

            len = in.readInt();
            OpenPublishedShares[] openShares = len == -1 ? null : new OpenPublishedShares[len];
            if (len != -1) {
                OpenPublishedShares share;
                for (int i = 0; i < openShares.length; i++) {
                    share = new OpenPublishedShares();
                    share.readExternal(in);
                    openShares[i] = share;
                }
            }
            return new ExtractedResponse(plainData, openShares);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
