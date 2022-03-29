package vss.benchmark;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.constant.KateCommitmentScheme;
import vss.commitment.linear.FeldmanCommitmentScheme;
import vss.polynomial.Polynomial;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PolynomialsEquivalence {
    private static final BigInteger p = new BigInteger("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16);
    private static final BigInteger field = new BigInteger("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16);
    private static final BigInteger generator = new BigInteger("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659", 16);
    private static final SecureRandom rndGenerator = new SecureRandom("ola".getBytes());
    private static final int nDecimals = 4;
    private static int threshold;
    private static int nTests;

    public static void main(String[] args) {
        threshold = Integer.parseInt(args[0]);
        nTests = Integer.parseInt(args[1]);
        int n = 3 * threshold + 1;
        BigInteger[] shareholders = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            shareholders[i] = BigInteger.valueOf(i + 1);
        }

        BigInteger x = BigInteger.ZERO;
        CommitmentScheme feldmanCommitmentScheme = new FeldmanCommitmentScheme(p, generator);
        System.out.println("Testing Feldman Commitment Scheme");
        test(feldmanCommitmentScheme, x);
        CommitmentScheme kateCommitmentScheme = new KateCommitmentScheme(threshold, shareholders);
        System.out.println("Testing Kate Commitment Scheme");
        test(kateCommitmentScheme, x);
    }

    private static void test(CommitmentScheme commitmentScheme, BigInteger x) {
        Measurement measurement = new Measurement(nTests);
        for (int i = 0; i < nTests; i++) {
            BigInteger constant = randomNumber(field.bitLength() - 1);
            Polynomial p1 = new Polynomial(field, threshold, constant, rndGenerator);
            Polynomial p2 = new Polynomial(field, threshold, constant, rndGenerator);

            Commitment p1Commitment = commitmentScheme.generateCommitments(p1, x);
            Commitment p2Commitment = commitmentScheme.generateCommitments(p2, x);

            measurement.start();
            for (int j = 0; j <= threshold; j++) {
                if (!commitmentScheme.checkValidityOfPolynomialsProperty(x, p1Commitment, p2Commitment)) {
                    throw new RuntimeException("Same polynomials returned false");
                }
            }
            measurement.stop();

            Polynomial p3 = new Polynomial(field, threshold, constant.add(BigInteger.TEN), rndGenerator);
            Commitment p3Commitment = commitmentScheme.generateCommitments(p3, x);

            if (commitmentScheme.checkValidityOfPolynomialsProperty(x, p1Commitment, p3Commitment))
                throw new RuntimeException("Different polynomials returned true");
        }
        double duration = measurement.getAverageInMillis(nDecimals);
        System.out.println("Duration: " + duration + " ms");
    }

    private static BigInteger randomNumber(int numBits) {
        BigInteger rndBig = new BigInteger(numBits, rndGenerator);
        if (rndBig.compareTo(BigInteger.ZERO) == 0)
            rndBig = rndBig.add(BigInteger.ONE);
        return rndBig;
    }
}
