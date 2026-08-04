package vss.commitment.linear.ec.c;

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
import java.util.Arrays;
import java.util.Map;

public class CECFeldmanCommitmentScheme implements CommitmentScheme {
	private final MathUtil mathUtil;

	public CECFeldmanCommitmentScheme() {
		this.mathUtil = new MathUtil();
	}

	public BigInteger getPrimeFieldOrder() {
		return mathUtil.getPrimeFieldOrder();
	}

	@Override
	public BigInteger getSubPrimeFieldOrder() {
		return mathUtil.getSubPrimeFieldOrder();
	}

	@Override
	public Commitment generateCommitments(Polynomial polynomial, BigInteger... additionalShareholders) {
		BigInteger[] coefficients = polynomial.getCoefficients();
		int degree = polynomial.getDegree();

		byte[][] commitments = new byte[degree + 1][];
		for (int i = 0; i < coefficients.length; i++) {
			commitments[i] = mathUtil.multiply(coefficients[i]);
		}
		return new RawLinearCommitment(commitments);
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
		byte[] leftSide = mathUtil.multiply(share.getShare());
		byte[] rightSize = computeRightSideOfVerification(share.getShareholder(), (RawLinearCommitment) commitment);

		return Arrays.equals(leftSide, rightSize);
	}

	public byte[] computeRightSideOfVerification(BigInteger shareholder, RawLinearCommitment commitment) {
		byte[][] commitments = commitment.getCommitment();

		byte[] gp = commitments[commitments.length - 1];
		for (int i = 0; i < commitments.length - 1; i++) {
			int k = commitments.length - 1 - i;
			BigInteger pow = shareholder.pow(k);
			byte[] mul = mathUtil.multiply(commitments[i], pow);
			gp = mathUtil.add(gp, mul);
		}

		return gp;
	}

	@Override
	public boolean checkValidityOfPolynomialsProperty(BigInteger x, Commitment... commitments) {
		byte[] rightSide = null;
		for (Commitment commitment : commitments) {
			if (rightSide == null) {
				rightSide = computeRightSideOfVerification(x, (RawLinearCommitment) commitment);
			} else if (!Arrays.equals(rightSide, computeRightSideOfVerification(x, (RawLinearCommitment) commitment))) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean checkValidityWithoutPreComputation(Share share, Commitment commitment) {
		return checkValidity(share, commitment);
	}

	@Override
	public Commitment sumCommitments(Commitment... commitments) throws SecretSharingException {
		int size = ((RawLinearCommitment) commitments[0]).getCommitment().length;
		byte[][][] ecCommitments = new byte[commitments.length][][];
		for (int i = 0; i < commitments.length; i++) {
			RawLinearCommitment c = (RawLinearCommitment) commitments[i];
			if (size != c.getCommitment().length)
				throw new SecretSharingException("Commitments must have same size");
			ecCommitments[i] = c.getCommitment();
		}

		byte[][] result = null;
		for (byte[][] ecCommitment : ecCommitments) {
			if (result == null) {
				result = new byte[size][];
				for (int j = 0; j < size; j++) {
					result[j] = Arrays.copyOf(ecCommitment[j], ecCommitment[j].length);
				}
				continue;
			}
			for (int j = 0; j < size; j++) {
				result[j] = mathUtil.add(result[j], ecCommitment[j]);
			}
		}
		return new RawLinearCommitment(result);
	}

	@Override
	public Commitment subtractCommitments(Commitment c1, Commitment c2) throws SecretSharingException {
		byte[][] l1 = ((RawLinearCommitment) c1).getCommitment();
		byte[][] l2 = ((RawLinearCommitment) c2).getCommitment();
		if (l1.length != l2.length)
			throw new SecretSharingException("Commitments must have same size");

		byte[][] result = new byte[l1.length][];
		for (int i = 0; i < result.length; i++) {
			result[i] = mathUtil.subtract(l1[i], l2[i]);
		}
		return new RawLinearCommitment(result);
	}

	@Override
	public Commitment addConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		byte[][] rawCommitments = ((RawLinearCommitment) commitment).getCommitment();
		byte[][] newCommitments = new byte[rawCommitments.length][];
		for (int i = 0; i < rawCommitments.length; i++) {
			newCommitments[i] = Arrays.copyOf(rawCommitments[i], rawCommitments[i].length);
		}
		byte[] commitmentToAdd = rawCommitments[newCommitments.length - 1];
		newCommitments[newCommitments.length - 1] = mathUtil.add(commitmentToAdd, mathUtil.multiply(constant));
		return new RawLinearCommitment(newCommitments);
	}

	@Override
	public Commitment subtractConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		byte[][] rawCommitments = ((RawLinearCommitment) commitment).getCommitment();
		byte[][] newCommitments = new byte[rawCommitments.length][];
		for (int i = 0; i < rawCommitments.length; i++) {
			newCommitments[i] = Arrays.copyOf(rawCommitments[i], rawCommitments[i].length);
		}
		byte[] commitmentToAdd = rawCommitments[newCommitments.length - 1];
		newCommitments[newCommitments.length - 1] = mathUtil.subtract(commitmentToAdd, mathUtil.multiply(constant));
		return new RawLinearCommitment(newCommitments);
	}


	public Commitment multiplyByConstant(Commitment commitment, BigInteger constant) {
		byte[][] commitments = ((RawLinearCommitment) commitment).getCommitment();
		byte[][] newCommitments = new byte[commitments.length][];
		for (int i = 0; i < commitments.length; i++) {
			newCommitments[i] = mathUtil.multiply(commitments[i], constant);
		}
		return new RawLinearCommitment(newCommitments);
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
	public Commitment recoverCommitment(BigInteger newShareholder, Map<BigInteger, Commitment> commitments) throws SecretSharingException {
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
			result = new RawLinearCommitment();
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
