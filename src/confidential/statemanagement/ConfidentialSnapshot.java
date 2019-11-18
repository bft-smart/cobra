package confidential.statemanagement;

import confidential.ConfidentialData;

import java.io.*;

public class ConfidentialSnapshot {
    private byte[] plainData;
    private ConfidentialData[] shares;

    public ConfidentialSnapshot(byte[] plainData, ConfidentialData... shares) {
        this.plainData = plainData;
        this.shares = shares;
    }

    public byte[] getPlainData() {
        return plainData;
    }

    public ConfidentialData[] getShares() {
        return shares;
    }

    public static ConfidentialSnapshot deserialize(byte[] serializedData) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedData);
             ObjectInput in = new ObjectInputStream(bis)) {
            int len = in.readInt();
            byte[] plainData = null;
            if (len > -1) {
                plainData = new byte[len];
                in.readFully(plainData);
            }

            len = in.readInt();
            ConfidentialData[] shares = null;
            if (len > -1) {
                shares = new ConfidentialData[len];
                ConfidentialData share;
                for (int i = 0; i < len; i++) {
                    share = new ConfidentialData();
                    share.readExternal(in);
                    shares[i] = share;
                }
            }
            return new ConfidentialSnapshot(plainData, shares);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] serialize() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
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
        }
        return null;
    }
}
