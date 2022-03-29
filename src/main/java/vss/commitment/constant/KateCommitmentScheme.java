package vss.commitment.constant;

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
import java.util.*;

/**
 * This class implements KAte et al. commitment scheme.
 * @author Robin
 */
public class KateCommitmentScheme implements CommitmentScheme {
    private final Pairing pairing;
    private final BigInteger[] shareholders;
    private final BigInteger[][] divisors;

    public KateCommitmentScheme(int threshold, BigInteger[] shareholders) {
        System.loadLibrary("Pairing");
        this.pairing = new Pairing(threshold);
        this.shareholders = shareholders;
        this.divisors = new BigInteger[shareholders.length][];
        for (int i = 0; i < shareholders.length; i++) {
            BigInteger shareholder = shareholders[i];
            BigInteger[] divisor = {
                    BigInteger.ONE,
                    shareholder.negate()
            };
            divisors[i] = divisor;
        }
    }

    public BigInteger getPrimeFieldOrder() {
        return pairing.getOrder();
    }

    @Override
    public Commitment generateCommitments(Polynomial polynomial, BigInteger... additionalShareholders) {
        BigInteger[] coefficients = polynomial.getCoefficients();
        BigInteger[] c = Arrays.copyOf(coefficients, coefficients.length);

        BigInteger field = pairing.getOrder();
        byte[] commitment = pairing.commitGivenCoefficients(coefficients);
        TreeMap<Integer, byte[]> witnesses = new TreeMap<>();
        for (int i = 0; i < shareholders.length; i++) {
            c[coefficients.length - 1] =
                    coefficients[coefficients.length - 1].subtract(polynomial
                    .evaluateAt(shareholders[i]));
            BigInteger[] w = Polynomial.divide(field, c, divisors[i]);
            byte[] witness = pairing.createWitnessGivenCoefficients(w);
            witnesses.put(shareholders[i].hashCode(), witness);
        }

        for (BigInteger shareholder : additionalShareholders) {
            c[coefficients.length - 1] =
                    coefficients[coefficients.length - 1].subtract(polynomial
                            .evaluateAt(shareholder));
            BigInteger[] divisor = {
                    BigInteger.ONE,
                    shareholder.negate()
            };
            BigInteger[] w = Polynomial.divide(field, c, divisor);
            byte[] witness = pairing.createWitnessGivenCoefficients(w);
            witnesses.put(shareholder.hashCode(), witness);
        }
        return new ConstantCommitment(commitment, witnesses);
    }

    @Override
    public void startVerification(Commitment commitment) {
        byte[] commitmentBytes;
        if (commitment instanceof ConstantCommitment)
            commitmentBytes = ((ConstantCommitment)commitment).getCommitment();
        else
            commitmentBytes = ((ShareCommitment)commitment).getCommitment();
        pairing.startVerification(commitmentBytes);
    }

    @Override
    public void endVerification() {
        pairing.endVerification();
    }

    @Override
    public void addShareholder(BigInteger shareholder) {

    }

    @Override
    public void removeShareholder(BigInteger shareholder) {

    }

    @Override
    public boolean checkValidity(Share share, Commitment commitment) {
        byte[] witness;
        if (commitment instanceof ConstantCommitment)
            witness = ((ConstantCommitment)commitment).getWitness(share.getShareholder());
        else
            witness = ((ShareCommitment)commitment).getWitness();
        return pairing.verifyShare(share.getShareholder(), share.getShare(), witness);
    }

    @Override
    public boolean checkValidityOfPolynomialsProperty(BigInteger x, Commitment... commitments) {
        byte[] partialResult = null;

        for (Commitment commitment : commitments) {
            ConstantCommitment constantCommitment = (ConstantCommitment) commitment;
            if (partialResult == null)
                partialResult = pairing.computePartialResult(x, constantCommitment);
            else if (!Arrays.equals(partialResult, pairing.computePartialResult(x, constantCommitment)))
                return false;
        }
        return true;
    }

    @Override
    public boolean checkValidityWithoutPreComputation(Share share, Commitment commitment) {
        byte[] commitmentBytes;
        byte[] witnessBytes;
        if (commitment instanceof ConstantCommitment) {
            ConstantCommitment constantCommitment = (ConstantCommitment)commitment;
            commitmentBytes = constantCommitment.getCommitment();
            witnessBytes = constantCommitment.getWitness(share.getShareholder());
        } else {
            ShareCommitment shareCommitment = (ShareCommitment) commitment;
            commitmentBytes = shareCommitment.getCommitment();
            witnessBytes = shareCommitment.getWitness();
        }
        return pairing.verifyShareWithoutPreComputation(share.getShareholder(), share.getShare(), commitmentBytes,
                witnessBytes);
    }

    @Override
    public Commitment sumCommitments(Commitment... commitments) throws SecretSharingException {
        CommitmentType type = getCommitmentType(commitments);
        if (type == null)
            throw new SecretSharingException("Commitments must have same type");
        if (type == CommitmentType.CONSTANT)
            return sumConstantCommitments(commitments);
        else if (type == CommitmentType.SHARE_COMMITMENT)
            return sumShareCommitments(commitments);

        return null;
    }

    @Override
    public Commitment subtractCommitments(Commitment c1, Commitment c2) throws SecretSharingException {
        if (!c1.getCommitmentType().equals(c2.getCommitmentType()))
            throw new SecretSharingException("Commitments must have same type");
        if (c1.getCommitmentType().equals(CommitmentType.CONSTANT))
            return subtractConstantCommitments(c1, c2);
        if (c2.getCommitmentType().equals(CommitmentType.SHARE_COMMITMENT))
            return subtractShareCommitments(c1, c2);
        return null;
    }

    private CommitmentType getCommitmentType(Commitment[] commitments) {
        CommitmentType firstType = null;
        for (Commitment commitment : commitments) {
            if (firstType == null) {
                if (commitment instanceof ConstantCommitment)
                    firstType = CommitmentType.CONSTANT;
                else if (commitment instanceof ShareCommitment)
                    firstType = CommitmentType.SHARE_COMMITMENT;
            } else {
                if (commitment instanceof ConstantCommitment && !firstType.equals(CommitmentType.CONSTANT))
                    return null;
                else if (commitment instanceof ShareCommitment && !firstType.equals(CommitmentType.SHARE_COMMITMENT))
                    return null;
            }
        }
        return firstType;
    }

    private Commitment subtractShareCommitments(Commitment c1, Commitment c2) {
        ShareCommitment s1 = (ShareCommitment) c1;
        ShareCommitment s2 = (ShareCommitment) c2;

        byte[] c = pairing.divideValues(s1.getCommitment(), s2.getCommitment());
        byte[] w = pairing.divideValues(s1.getWitness(), s2.getWitness());
        return new ShareCommitment(c, w);
    }

    private Commitment sumShareCommitments(Commitment[] commitments) {
        byte[][] commitmentsBytes = new byte[commitments.length][];
        byte[][] witnesses = new byte[commitments.length][];
        for (int i = 0; i < commitments.length; i++) {
            ShareCommitment shareCommitment = (ShareCommitment) commitments[i];
            witnesses[i] = shareCommitment.getWitness();
            commitmentsBytes[i] = shareCommitment.getCommitment();
        }

        byte[] commitmentResult = pairing.multiplyValues(commitmentsBytes);
        byte[] witnessResult = pairing.multiplyValues(witnesses);

        return new ShareCommitment(commitmentResult, witnessResult);
    }

    private Commitment subtractConstantCommitments(Commitment c1, Commitment c2) throws SecretSharingException {
        ConstantCommitment constantC1 = (ConstantCommitment) c1;
        ConstantCommitment constantC2 = (ConstantCommitment) c2;
        Set<Integer> shareholders = new HashSet<>(constantC1.getWitnesses().keySet());

        if (shareholders.size() != constantC2.getWitnesses().keySet().size()) {
            throw new SecretSharingException("Commitments contain witness from different shareholders");
        }

        for (Integer shareholderHash : constantC2.getWitnesses().keySet()) {
            if (!shareholders.contains(shareholderHash)) {
                throw new SecretSharingException("Commitments contain witness from different shareholders");
            }
        }

        byte[] c = pairing.divideValues(constantC1.getCommitment(), constantC2.getCommitment());
        TreeMap<Integer, byte[]> w = new TreeMap<>();
        Iterator<Map.Entry<Integer, byte[]>> i1 = constantC1.getWitnesses().entrySet().iterator();
        Iterator<Map.Entry<Integer, byte[]>> i2 = constantC2.getWitnesses().entrySet().iterator();

        while (i1.hasNext()) {
            Map.Entry<Integer, byte[]> e1 = i1.next();
            Map.Entry<Integer, byte[]> e2 = i2.next();
            byte[] witness = pairing.divideValues(e1.getValue(), e2.getValue());
            w.put(e1.getKey(), witness);
        }

        return new ConstantCommitment(c, w);
    }

    private Commitment sumConstantCommitments(Commitment[] commitments) throws SecretSharingException {
        ConstantCommitment[] constantCommitments = new ConstantCommitment[commitments.length];
        Set<Integer> shareholders = new HashSet<>(((ConstantCommitment)commitments[0]).getWitnesses().keySet());
        byte[][] commitmentsBytes = new byte[commitments.length][];

        for (int i = 0; i < commitments.length; i++) {
            ConstantCommitment constantCommitment = (ConstantCommitment)commitments[i];
            constantCommitments[i] = constantCommitment;
            Map<Integer, byte[]> witnesses = constantCommitment.getWitnesses();

            if (shareholders.size() != witnesses.keySet().size()) {
                throw new SecretSharingException("Commitments contain witness from different shareholders");
            }

            for (Integer shareholderHash : witnesses.keySet()) {
                if (!shareholders.contains(shareholderHash)) {
                    throw new SecretSharingException("Commitments contain witness from different shareholders");
                }
            }
            commitmentsBytes[i] = constantCommitment.getCommitment();
        }

        Map<Integer, byte[][]> witnessToSum = new HashMap<>(shareholders.size());
        for (Integer shareholder : shareholders) {
            byte[][] witnesses = new byte[constantCommitments.length][];
            for (int i = 0; i < constantCommitments.length; i++) {
                witnesses[i] = constantCommitments[i].getWitness(shareholder);
            }
            witnessToSum.put(shareholder, witnesses);
        }

        byte[] commitmentResult = pairing.multiplyValues(commitmentsBytes);
        TreeMap<Integer, byte[]> witnessesResult = new TreeMap<>();

        for (Map.Entry<Integer, byte[][]> entry : witnessToSum.entrySet()) {
            witnessesResult.put(entry.getKey(), pairing.multiplyValues(entry.getValue()));
        }

        return new ConstantCommitment(commitmentResult, witnessesResult);
    }

    @Override
    public Commitment extractCommitment(BigInteger shareholder, Commitment commitment) {
        ConstantCommitment constantCommitment = (ConstantCommitment)commitment;
        return new ShareCommitment(constantCommitment.getCommitment(),
                constantCommitment.getWitness(shareholder));
    }

    /**
     * @requires Commitments must be of type {@link ShareCommitment}
     */
    @Override
    public Commitment combineCommitments(Map<BigInteger, Commitment> commitments) {
        byte[] resultCommitment = null;
        TreeMap<Integer, byte[]> resultWitnesses = new TreeMap<>();
        for (Map.Entry<BigInteger, Commitment> entry : commitments.entrySet()) {
            ShareCommitment shareCommitment = (ShareCommitment)entry.getValue();
            if (resultCommitment == null)
                resultCommitment = shareCommitment.getCommitment();
            resultWitnesses.put(entry.getKey().hashCode(),
                    shareCommitment.getWitness());
        }
        return new ConstantCommitment(resultCommitment, resultWitnesses);
    }

    @Override
    public Commitment recoverCommitment(BigInteger newShareholder,
                                        Map<BigInteger, Commitment> commitments) throws SecretSharingException {
        byte[] recoveredWitness = pairing.recoverWitness(newShareholder, commitments);
        for (Commitment value : commitments.values()) {
            byte[] commitment =
                    ((ShareCommitment)value).getCommitment();
            return new ShareCommitment(commitment, recoveredWitness);
        }
        return null;
    }

    @Override
    public Commitment readCommitment(ObjectInput in) throws IOException, ClassNotFoundException {
        CommitmentType commitmentType = CommitmentType.getType(in.read());
        Commitment result = null;
        switch (commitmentType) {
            case CONSTANT:
                result = new ConstantCommitment();
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
