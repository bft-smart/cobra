package confidential.encrypted;

import java.io.*;
import java.util.Arrays;

public class EncryptedConfidentialMessage {
    private final byte[] plainData;
    private final EncryptedConfidentialData[] shares;

    public EncryptedConfidentialMessage() {
        plainData = null;
        shares = null;
    }

    public EncryptedConfidentialMessage(byte[] plainData, EncryptedConfidentialData... shares) {
        this.plainData = plainData;
        this.shares = shares;
    }

    public byte[] getPlainData() {
        return plainData;
    }

    public EncryptedConfidentialData[] getShares() {
        return shares;
    }

    public byte[] serialize() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeInt(plainData == null ? -1 : plainData.length);
            if (plainData != null)
                out.write(plainData);
            out.writeInt(shares == null ? -1 : shares.length);
            if (shares != null) {
                for (EncryptedConfidentialData share : shares)
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

    public static EncryptedConfidentialMessage deserialize(byte[] serializedData) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedData);
             ObjectInput in = new ObjectInputStream(bis)) {
            int len = in.readInt();
            byte[] plainData = len == -1 ? null : new byte[len];
            if (len != -1)
                in.readFully(plainData);

            len = in.readInt();
            EncryptedConfidentialData[] shares = len == -1 ? null : new EncryptedConfidentialData[len];
            if (len != -1) {
                EncryptedConfidentialData share;
                for (int i = 0; i < shares.length; i++) {
                    share = new EncryptedConfidentialData();
                    share.readExternal(in);
                    shares[i] = share;
                }
            }
            return new EncryptedConfidentialMessage(plainData, shares);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedConfidentialMessage that = (EncryptedConfidentialMessage) o;
        if (!Arrays.equals(plainData, that.plainData))
            return false;
        if (shares == null && that.shares == null)
            return true;
        if (shares == null || that.shares == null)
            return false;
        if (shares.length != that.shares.length)
            return false;
        for (int i = 0; i < shares.length; i++)
            if (!shares[i].equals(that.shares[i]))
                return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(plainData);
        if (shares != null) {
            for (EncryptedConfidentialData share : shares) {
                result = 31 * result + share.hashCode();
            }
        }
        return result;
    }

    @Override
    public String toString() {
        return String.format("[plainData: %s - shares: %s]", Arrays.toString(plainData), Arrays.toString(shares));
    }
}
