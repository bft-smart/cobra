package vss.commitment.ellipticCurve;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import vss.commitment.Commitment;
import vss.commitment.CommitmentType;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Arrays;

/**
 * This class stores array of commitment values based on elliptic curve
 * @author robin
 */
public class EllipticCurveCommitment implements Commitment {
	private ECPoint[] commitment;
	private final ECCurve curve;

	public EllipticCurveCommitment(ECCurve curve) {
		this.curve = curve;
	}

	public EllipticCurveCommitment(ECPoint[] commitment, ECCurve curve) {
		this.commitment = commitment;
		this.curve = curve;
	}

	public ECPoint[] getCommitment() {
		return commitment;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		EllipticCurveCommitment that = (EllipticCurveCommitment) o;
		return Arrays.equals(commitment, that.commitment);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(commitment);
	}

	@Override
	public String toString() {
		return Arrays.toString(commitment);
	}

	@Override
	public CommitmentType getCommitmentType() {
		return CommitmentType.ELLIPTIC_CURVE;
	}

	@Override
	public int consistentHash() {
		return hashCode();
	}

	@Override
	public boolean isOfSameSecret(Commitment commitment) {
		return equals(commitment);
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(commitment == null ? -1 : commitment.length);
		if (commitment != null) {
			for (ECPoint point : commitment) {
				byte[] encoded = point.getEncoded(true);
				out.writeInt(encoded.length);
				out.write(encoded);
			}
		}
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		int len = in.readInt();
		if (len != -1) {
			commitment = new ECPoint[len];
			for (int i = 0; i < len; i++) {
				byte[] encoded = new byte[in.readInt()];
				in.readFully(encoded);
				commitment[i] = curve.decodePoint(encoded);
			}
		}
	}
}
