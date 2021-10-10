package confidential;

import vss.secretsharing.VerifiableShare;

import java.io.*;
import java.util.Arrays;

public class ConfidentialMessage {
    private final byte[] plainData;
    private final VerifiableShare[] shares;

    public ConfidentialMessage() {
        plainData = null;
        shares = null;
    }

    public ConfidentialMessage(byte[] plainData, VerifiableShare... shares) {
        this.plainData = plainData;
        this.shares = shares;
    }

    public byte[] getPlainData() {
        return plainData;
    }

    public VerifiableShare[] getShares() {
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
                for (VerifiableShare share : shares)
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

    public static ConfidentialMessage deserialize(byte[] serializedData) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedData);
             ObjectInput in = new ObjectInputStream(bis)) {
            int len = in.readInt();
            byte[] plainData = len == -1 ? null : new byte[len];
            if (len != -1)
                in.readFully(plainData);

            len = in.readInt();
            VerifiableShare[] shares = len == -1 ? null : new VerifiableShare[len];
            if (len != -1) {
                VerifiableShare share;
                for (int i = 0; i < shares.length; i++) {
                    share = new VerifiableShare();
                    share.readExternal(in);
                    shares[i] = share;
                }
            }
            return new ConfidentialMessage(plainData, shares);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ConfidentialMessage that = (ConfidentialMessage) o;
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
            for (VerifiableShare share : shares) {
                result = 31 * result + Arrays.hashCode(share.getSharedData());
                result = 31 * result + share.getCommitments().consistentHash();
            }
        }
        return result;
    }

    @Override
    public String toString() {
        return String.format("[plainData: %s - shares: %s]", Arrays.toString(plainData), Arrays.toString(shares));
    }
}
