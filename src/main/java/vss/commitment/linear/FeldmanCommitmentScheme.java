package vss.commitment.linear;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentSchemeType;
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

/**
 * This class implements Feldman Verifiable Secret Sharing scheme (only commitments)
 *
 * @author Robin
 */
public class FeldmanCommitmentScheme implements CommitmentScheme {
    /*
     * Generator of multiplicative cyclic group p of order q.
     * p and q are prime numbers.
     */
    private final BigInteger generator;
    private final BigInteger primeFieldOrder;
    private final BigInteger subPrimeFieldOrder;

    public FeldmanCommitmentScheme(BigInteger primeFieldOrder, BigInteger generator, BigInteger subPrimeFieldOrder) {
        this.primeFieldOrder = primeFieldOrder;
        this.generator = generator;
        this.subPrimeFieldOrder = subPrimeFieldOrder;
    }

	@Override
	public CommitmentSchemeType getCommitmentSchemeType() {
		return CommitmentSchemeType.FELDMAN_SCHEME;
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

        BigInteger[] commitments = new BigInteger[degree + 1];
        for (int i = coefficients.length - degree - 1, j = 0; i < coefficients.length; i++, j++) {
            commitments[j] = generator.modPow(coefficients[i], primeFieldOrder);
        }
        return new LinearCommitments(commitments);
    }

	@Override
    public void addShareholder(BigInteger shareholder) {
		throw new UnsupportedOperationException("TODO");
    }

    @Override
    public void removeShareholder(BigInteger shareholder) {
		throw new UnsupportedOperationException("TODO");
    }

	/**
     * Returns (g^at)^(i^t) * ... * (g^a1)^(i^1) * (g^a0)
     * @param x Shareholder ID
     * @param commitments Feldman's commitment
     * @return (g^at)^(i^t) * ... * (g^a1)^(i^1) * (g^a0)
     */
    private BigInteger computeRightSideOfVerification(BigInteger x, LinearCommitments commitments) {
        BigInteger[] c = commitments.getCommitments();

        BigInteger gp = BigInteger.ONE;
        for (int j = 0,t = c.length - 1; j < c.length; j++, t--) {
            BigInteger ij = x.modPow(BigInteger.valueOf(t), primeFieldOrder); //TODO pre-compute
            gp = gp.multiply(c[j].modPow(ij, primeFieldOrder)).mod(primeFieldOrder);
        }

        return gp;
    }

    @Override
    public boolean checkValidityOfPolynomialsProperty(BigInteger x, Commitment... commitments) {
        BigInteger rightSide = null;
        for (Commitment commitment : commitments) {
            if (rightSide == null)
                rightSide = computeRightSideOfVerification(x, (LinearCommitments) commitment);
            else if (!rightSide.equals(computeRightSideOfVerification(x, (LinearCommitments) commitment)))
                return false;
        }
        return true;
    }

    @Override
    public boolean checkValidityWithoutPreComputation(Share share, Commitment commitment) {
		LinearCommitments commitments = (LinearCommitments)commitment;
		BigInteger gs = generator.modPow(share.getShare(), primeFieldOrder);
		BigInteger gp = computeRightSideOfVerification(share.getShareholder(), commitments);

		return gs.equals(gp);
    }

    @Override
    public Commitment sumCommitments(Commitment... commitments) throws SecretSharingException {
        int size = ((LinearCommitments) commitments[0]).getCommitments().length;
        BigInteger[][] linearCommitments = new BigInteger[commitments.length][];
        for (int i = 0; i < commitments.length; i++) {
            LinearCommitments lc = (LinearCommitments)commitments[i];
            if (size != lc.getCommitments().length)
                throw new SecretSharingException("Commitments must have same size");
            linearCommitments[i] = lc.getCommitments();
        }

        BigInteger[] result = new BigInteger[size];
        Arrays.fill(result, BigInteger.ONE);
        for (BigInteger[] l : linearCommitments) {
            for (int j = 0; j < l.length; j++) {
                result[j] = result[j].multiply(l[j]).mod(primeFieldOrder);
            }
        }

        return new LinearCommitments(result);
    }

    @Override
    public Commitment subtractCommitments(Commitment c1, Commitment c2) throws SecretSharingException {
        BigInteger[] l1 = ((LinearCommitments) c1).getCommitments();
        BigInteger[] l2 = ((LinearCommitments) c2).getCommitments();
        if (l1.length != l2.length)
            throw new SecretSharingException("Commitments must have same size");
        BigInteger[] result = new BigInteger[l1.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = l1[i].multiply(l2[i].modInverse(primeFieldOrder)).mod(primeFieldOrder);
        }

        return new LinearCommitments(result);
    }

	@Override
	public Commitment addConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		BigInteger[] rawCommitments = ((LinearCommitments) commitment).getCommitments();
		BigInteger[] newCommitments = new BigInteger[rawCommitments.length];
		System.arraycopy(rawCommitments, 0, newCommitments, 0, rawCommitments.length);
		newCommitments[newCommitments.length - 1] = generator.modPow(constant, primeFieldOrder).multiply(rawCommitments[rawCommitments.length - 1]).mod(primeFieldOrder);
		return new LinearCommitments(newCommitments);
	}

	@Override
	public Commitment subtractConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		BigInteger[] rawCommitments = ((LinearCommitments) commitment).getCommitments();
		BigInteger[] newCommitments = new BigInteger[rawCommitments.length];
		System.arraycopy(rawCommitments, 0, newCommitments, 0, rawCommitments.length);
		newCommitments[newCommitments.length - 1] = rawCommitments[rawCommitments.length - 1]
				.multiply(generator.modPow(constant, primeFieldOrder).modInverse(primeFieldOrder)).mod(primeFieldOrder);
		return new LinearCommitments(newCommitments);
	}

	@Override
	public Commitment multiplyByConstant(Commitment commitment, BigInteger constant) throws SecretSharingException {
		BigInteger[] rawCommitments = ((LinearCommitments) commitment).getCommitments();
		BigInteger[] result = new BigInteger[rawCommitments.length];
		for (int i = 0; i < rawCommitments.length; i++) {
			result[i] = rawCommitments[i].modPow(constant, primeFieldOrder);
		}
		return new LinearCommitments(result);
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
		Commitment selectedCommitment = null;
		int selectedCommitmentHash = -1;
		for (Commitment value : commitments.values()) {
			if (selectedCommitment == null) {
				selectedCommitment = value;
				selectedCommitmentHash = value.consistentHash();
			} else if (selectedCommitmentHash != value.consistentHash()) {
				throw new SecretSharingException("Commitments are different");
			}
		}
		return selectedCommitment;
    }

    @Override
    public Commitment readCommitment(ObjectInput in) throws IOException, ClassNotFoundException {
        CommitmentType commitmentType = CommitmentType.getType(in.read());
        Commitment result = null;
        switch (commitmentType) {
            case LINEAR:
			case SHARE_COMMITMENT:
				result = new LinearCommitments();
                break;
		}
        if (result == null)
            return null;
        result.readExternal(in);
        return result;
    }

    @Override
    public void writeCommitment(Commitment commitment, ObjectOutput out) throws IOException {
        out.write(commitment.getCommitmentType().ordinal());
        commitment.writeExternal(out);
    }
}
