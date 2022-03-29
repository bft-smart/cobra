package vss.commitment.linear;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentType;
import vss.commitment.constant.ShareCommitment;
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
    private final BigInteger p;

    public FeldmanCommitmentScheme(BigInteger p, BigInteger generator) {
        this.p = p;
        this.generator = generator;
    }

    @Override
    public Commitment generateCommitments(Polynomial polynomial, BigInteger... additionalShareholders) {
        BigInteger[] coefficients = polynomial.getCoefficients();
        int degree = polynomial.getDegree();

        BigInteger[] commitments = new BigInteger[degree + 1];
        for (int i = coefficients.length - degree - 1, j = 0; i < coefficients.length; i++, j++) {
            commitments[j] = generator.modPow(coefficients[i], p);
        }
        return new LinearCommitments(commitments);
    }

    @Override
    public void startVerification(Commitment commitment) {

    }

    @Override
    public void endVerification() {

    }

    @Override
    public void addShareholder(BigInteger shareholder) {

    }

    @Override
    public void removeShareholder(BigInteger shareholder) {

    }

    /**
     * P(x)=atx^t + ... + a1x^1 + a0
     * commitment = [g^at, ..., g^a1, g^a0]
     * verification of share (i, P(i)): g^P(i) ?= (g^at)^(i^t) * ... * (g^a1)^(i^1) * (g^a0)
     * @param share Share to verify
     * @param commitment Commitment of the polynomial
     * @return True if share is on polynomial, false otherwise
     */
    @Override
    public boolean checkValidity(Share share, Commitment commitment) {
        LinearCommitments commitments = (LinearCommitments)commitment;
        BigInteger gs = generator.modPow(share.getShare(), p);
        BigInteger gp = computeRightSideOfVerification(share.getShareholder(), commitments);

        return gs.equals(gp);
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
            BigInteger ij = x.modPow(BigInteger.valueOf(t), p); //TODO pre-compute
            gp = gp.multiply(c[j].modPow(ij, p)).mod(p);
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
        return checkValidity(share, commitment);
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
                result[j] = result[j].multiply(l[j]).mod(p);
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
            result[i] = l1[i].multiply(l2[i].modInverse(p)).mod(p);
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
        switch (commitmentType) {
            case LINEAR:
                result = new LinearCommitments();
                break;
            case SHARE_COMMITMENT:
                result = new ShareCommitment();
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
