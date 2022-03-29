package vss.secretsharing;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Stores shareholder and its share
 *
 * @author Robin
 */
public class Share implements Externalizable {
    private BigInteger shareholder;
    private BigInteger share;

    public Share() {}

    public Share(BigInteger shareholder, BigInteger share) {
        this.shareholder = shareholder;
        this.share = share;
    }

    public BigInteger getShareholder() {
        return shareholder;
    }

    public BigInteger getShare() {
        return share;
    }

    public void setShareholder(BigInteger shareholder) {
        this.shareholder = shareholder;
    }

    public void setShare(BigInteger share) {
        this.share = share;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Share share1 = (Share) o;
        return Objects.equals(shareholder, share1.shareholder) &&
                Objects.equals(share, share1.share);
    }

    @Override
    public int hashCode() {
        return Objects.hash(shareholder, share);
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        byte[] b = shareholder.toByteArray();
        out.writeInt(b.length);
        out.write(b);

        b = share.toByteArray();
        out.writeInt(b.length);
        out.write(b);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        byte[] b = new byte[in.readInt()];
        in.readFully(b);
        shareholder = new BigInteger(b);

        b = new byte[in.readInt()];
        in.readFully(b);
        share = new BigInteger(b);
    }

    @Override
    public String toString() {
        return "(" + shareholder + ", " + share + ")";
    }
}
