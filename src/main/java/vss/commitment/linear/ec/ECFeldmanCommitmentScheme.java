package vss.commitment.linear.ec;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentType;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Map;

/**
 * This class implements Feldman's verifiable secret sharing scheme based on elliptic curve (only the commitments)
 *
 * @author robin
 */
public class ECFeldmanCommitmentScheme implements CommitmentScheme {
	private final ECCurve curve;
	private final ECPoint generator;
	private final BigInteger primeFieldOrder;
	private final BigInteger subPrimeFieldOrder;

	public ECFeldmanCommitmentScheme(BigInteger prime, BigInteger order, BigInteger a, BigInteger b,
	                                 byte[] compressedGenerator) {
		this.primeFieldOrder = prime;
		this.subPrimeFieldOrder = order;
		BigInteger cofactor = prime.divide(order);
		this.curve = new ECCurve.Fp(prime, a, b, order, cofactor);
		this.generator = curve.decodePoint(compressedGenerator);
	}

	public byte[] encodePoint(ECPoint point) {
		return point.getEncoded(true);
	}

	public ECPoint decodePoint(byte[] encodedPoint) {
		return curve.decodePoint(encodedPoint);
	}

	@Override
	public BigInteger getPrimeFieldOrder() {
		return primeFieldOrder;
	}

	@Override
	public BigInteger getSubPrimeFieldOrder() {
		return subPrimeFieldOrder;
	}

	@Override
	public Commitment generateCommitments(Polynomial polynomial, BigInteger... additionalShareholders) {
		BigInteger[] coefficients = polynomial.getCoefficients();
		int degree = polynomial.getDegree();

		ECPoint[] commitment = new ECPoint[degree + 1];
		for (int i = 0; i < coefficients.length; i++) {
			commitment[i] = generator.multiply(coefficients[i]);
		}
		return new ECLinearCommitment(commitment, curve);
	}

	@Override
	public void startVerification(Commitment commitment) {
	}

	@Override
	public void endVerification() {
	}

	@Override
	public void addShareholder(BigInteger shareholder) {
		throw new UnsupportedOperationException("TODO");
	}

	@Override
	public void removeShareholder(BigInteger shareholder) {
		throw new UnsupportedOperationException("TODO");
	}

	@Override
	public boolean checkValidity(Share share, Commitment commitment) {
		ECPoint leftSide = generator.multiply(share.getShare());
		ECPoint rightSide = computeRightSideOfVerification(share.getShareholder(),
				(ECLinearCommitment) commitment);
		return leftSide.equals(rightSide);
	}

	private ECPoint computeRightSideOfVerification(BigInteger x, ECLinearCommitment commitment) {
		ECPoint[] c = commitment.getCommitment();

		ECPoint gp = c[c.length - 1];
		for (int i = 0; i < c.length - 1; i++) {
			int k = c.length - 1 - i;
			gp = gp.add(c[i].multiply(x.pow(k)));
		}

		return gp;
	}

	@Override
	public boolean checkValidityOfPolynomialsProperty(BigInteger x, Commitment... commitments) {
		ECPoint rightSide = null;
		for (Commitment commitment : commitments) {
			if (rightSide == null)
				rightSide = computeRightSideOfVerification(x, (ECLinearCommitment) commitment);
			else if (!rightSide.equals(computeRightSideOfVerification(x, (ECLinearCommitment) commitment)))
				return false;
		}
		return true;
	}

	@Override
	public boolean checkValidityWithoutPreComputation(Share share, Commitment commitment) {
		return checkValidity(share, commitment);
	}

	@Override
	public Commitment sumCommitments(Commitment... commitments) throws SecretSharingException {
		int size = ((ECLinearCommitment) commitments[0]).getCommitment().length;
		ECPoint[][] ecCommitments = new ECPoint[commitments.length][];
		for (int i = 0; i < commitments.length; i++) {
			ECLinearCommitment lc = (ECLinearCommitment)commitments[i];
			if (size != lc.getCommitment().length)
				throw new SecretSharingException("Commitments must have same size");
			ecCommitments[i] = lc.getCommitment();
		}

		ECPoint[] result = ecCommitments[0];
		for (int i = 1; i < ecCommitments.length; i++) {
			for (int j = 0; j < size; j++) {
				result[j] = result[j].add(ecCommitments[i][j]);
			}
		}

		return new ECLinearCommitment(result, curve);
	}

	@Override
	public Commitment subtractCommitments(Commitment c1, Commitment c2) throws SecretSharingException {
		ECPoint[] l1 = ((ECLinearCommitment) c1).getCommitment();
		ECPoint[] l2 = ((ECLinearCommitment) c2).getCommitment();
		if (l1.length != l2.length)
			throw new SecretSharingException("Commitments must have same size");
		ECPoint[] result = new ECPoint[l1.length];
		for (int i = 0; i < result.length; i++) {
			result[i] = l1[i].subtract(l2[i]);
		}

		return new ECLinearCommitment(result, curve);
	}

	@Override
	public Commitment addConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		ECPoint[] rawCommitments = ((ECLinearCommitment) commitment).getCommitment();
		ECPoint[] newCommitments = new ECPoint[rawCommitments.length + 1];
		System.arraycopy(rawCommitments, 0, newCommitments, 0, rawCommitments.length);
		newCommitments[newCommitments.length - 1] = generator.multiply(constant).add(rawCommitments[rawCommitments.length - 1]);
		return new ECLinearCommitment(newCommitments, curve);
	}

	@Override
	public Commitment subtractConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		ECPoint[] rawCommitments = ((ECLinearCommitment) commitment).getCommitment();
		ECPoint[] newCommitments = new ECPoint[rawCommitments.length + 1];
		System.arraycopy(rawCommitments, 0, newCommitments, 0, rawCommitments.length);
		newCommitments[newCommitments.length - 1] = rawCommitments[rawCommitments.length - 1].subtract(generator.multiply(constant));
		return new ECLinearCommitment(newCommitments, curve);
	}

	@Override
	public Commitment multiplyByConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		ECPoint[] rawCommitment = ((ECLinearCommitment) commitment).getCommitment();
		ECPoint[] result = new ECPoint[rawCommitment.length];
		for (int i = 0; i < rawCommitment.length; i++) {
			result[i] = rawCommitment[i].multiply(constant);
		}
		return new ECLinearCommitment(result, curve);
	}

	@Override
	public Commitment extractCommitment(BigInteger shareholder, Commitment commitment) {
		return commitment;
	}

	@Override
	public Commitment combineCommitments(Map<BigInteger, Commitment> commitments) {
		for (Commitment value : commitments.values()) {
			return value;
		}
		return null;
	}

	@Override
	public Commitment recoverCommitment(BigInteger newShareholder, Map<BigInteger, Commitment> commitments) {
		for (Commitment value : commitments.values()) {
			return value;
		}
		return null;
	}

	@Override
	public Commitment readCommitment(ObjectInput in) throws IOException, ClassNotFoundException {
		CommitmentType commitmentType = CommitmentType.getType(in.read());
		Commitment result = null;
		if (commitmentType == CommitmentType.ELLIPTIC_CURVE) {
			result = new ECLinearCommitment(curve);
			result.readExternal(in);
		}
		return result;
	}

	@Override
	public void writeCommitment(Commitment commitment, ObjectOutput out) throws IOException {
		out.write(commitment.getCommitmentType().ordinal());
		commitment.writeExternal(out);
	}
}
