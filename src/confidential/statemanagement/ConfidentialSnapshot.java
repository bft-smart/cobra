package confidential.statemanagement;

import vss.secretsharing.VerifiableShare;

import java.io.*;

public class ConfidentialSnapshot {
    private byte[] plainData;
    private VerifiableShare[] shares;

    public ConfidentialSnapshot(byte[] plainData, VerifiableShare... shares) {
        this.plainData = plainData;
        this.shares = shares;
    }

    public byte[] getPlainData() {
        return plainData;
    }

    public VerifiableShare[] getShares() {
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
            VerifiableShare[] shares = null;
            if (len > -1) {
                shares = new VerifiableShare[len];
                VerifiableShare share;
                for (int i = 0; i < len; i++) {
                    share = new VerifiableShare();
                    share.readExternal(in);
                    shares[i] = share;
                }
            }
            return new ConfidentialSnapshot(plainData, shares);
        } catch (IOException e) {
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
                for (VerifiableShare share : shares)
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
