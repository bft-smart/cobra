package vss.commitment.constant;

import vss.commitment.Commitment;
import vss.facade.SecretSharingException;

import java.math.BigInteger;
import java.util.Map;

/**
 * @author Robin
 */
public class Pairing {
    private native void initialize(int threshold);
    private native byte[] getOrderBytes();

    private native byte[] commit(String... coefficients);
    private native byte[] createWitness(String... coefficients);

    /**
     * Returns e(C, g) / e(w_x, g^a / g^i)
     * @param x Shareholder ID
     * @param commitment Commitment
     * @param witness x's witness
     * @return e(C, g) / e(w_x, g^a / g^i)
     */
    private native byte[] computePartialVerification(byte[] x, byte[] commitment, byte[] witness);
    private native boolean verify(byte[] x, byte[] y, byte[] witness);
    private native boolean verifyWithoutPreComputation(byte[] x, byte[] y, byte[] commitment, byte[] witness);
    public native void endVerification();
    public native void startVerification(byte[] commitment);

    public native byte[] multiplyValues(byte[]... values);

    /**
     * Computes a/b
     * @param a Value a
     * @param b Value b
     * @return a/b
     */
    public native byte[] divideValues(byte[] a, byte[] b);

    private native byte[] interpolateAndEvaluateAt(byte[] i, byte[][]... values);

    public native void close();

    private final BigInteger order;

    public Pairing(int threshold) {
        initialize(threshold);
        this.order = new BigInteger(1, getOrderBytes());
    }

    public BigInteger getOrder() {
        return order;
    }

    byte[] commitGivenCoefficients(BigInteger... coefficients) {
        String[] stringCoefficients = toStringArray(coefficients);
        return commit(stringCoefficients);
    }

    byte[] createWitnessGivenCoefficients(BigInteger... coefficients) {
        String[] stringCoefficients = toStringArray(coefficients);
        return createWitness(stringCoefficients);
    }

    byte[] computePartialResult(BigInteger x, ConstantCommitment commitment) {
       return computePartialVerification(x.toByteArray(), commitment.getCommitment(), commitment.getWitness(x));
    }

    boolean verifyShare(BigInteger shareholder, BigInteger share, byte[] witness) {
        return verify(shareholder.toByteArray(), share.toByteArray(), witness);
    }

    boolean verifyShareWithoutPreComputation(BigInteger shareholder, BigInteger share, byte[] commitment, byte[] witness) {
        return verifyWithoutPreComputation(shareholder.toByteArray(), share.toByteArray(), commitment, witness);
    }

    private static String[] toStringArray(BigInteger... numbers) {
        String[] result = new String[numbers.length];

        for (int i = 0; i < numbers.length; i++) {
            result[i] = numbers[i].toString(16);
        }
        return result;
    }

    byte[] recoverWitness(BigInteger shareholder, Map<BigInteger, Commitment> commitments) throws SecretSharingException {
        byte[][][] witnesses = new byte[commitments.size()][][];
        int i = 0;
        for (Map.Entry<BigInteger, Commitment> entry : commitments.entrySet()) {
            byte[][] shareholderAndWitness = new byte[2][];
            shareholderAndWitness[0] = entry.getKey().toByteArray();
            shareholderAndWitness[1] =
                    ((ShareCommitment)entry.getValue()).getWitness();
            witnesses[i] = shareholderAndWitness;
            i++;
        }
        try {
            return interpolateAndEvaluateAt(shareholder.toByteArray(), witnesses);
        } catch (IllegalStateException e) {
            throw new SecretSharingException("Witness recovery polynomial has incorrect" +
                    " degree");
        }
    }
}
