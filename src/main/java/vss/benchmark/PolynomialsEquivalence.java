package vss.benchmark;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentSchemeFactory;
import vss.polynomial.Polynomial;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PolynomialsEquivalence {
	private static final SecureRandom rndGenerator = new SecureRandom("ola".getBytes());
	private static final int nDecimals = 4;
	private static int threshold;
	private static int nTests;

	public static void main(String[] args) {
		if (args.length != 3) {
			System.out.println("USAGE: ... vss.benchmark.PolynomialsEquivalence <threshold> <num tests> " +
					"<commitment scheme type: linear|ec_linear|c_ec_linear|dl_kzg|ped_kzg>");
			System.exit(-1);
		}
		threshold = Integer.parseInt(args[0]);
		nTests = Integer.parseInt(args[1]);
		String commitmentSchemeType = args[2];
		int n = 3 * threshold + 1;
		BigInteger[] shareholders = new BigInteger[n];
		for (int i = 0; i < n; i++) {
			shareholders[i] = BigInteger.valueOf(i + 1);
		}

		BigInteger x = BigInteger.ZERO;
		CommitmentScheme commitmentScheme = CommitmentSchemeFactory.createCommitmentScheme(commitmentSchemeType,
				threshold, shareholders);
		test(commitmentScheme, x);
	}

	private static void test(CommitmentScheme commitmentScheme, BigInteger x) {
		Measurement measurement = new Measurement(nTests);
		BigInteger field = commitmentScheme.getSubPrimeFieldOrder();
		for (int i = 0; i < nTests; i++) {
			BigInteger constant = randomNumber(field.bitLength() - 1);
			Polynomial p1 = new Polynomial(field, threshold, constant, rndGenerator);
			Polynomial p2 = new Polynomial(field, threshold, constant, rndGenerator);

			Commitment p1Commitment = commitmentScheme.generateCommitments(p1, x);
			Commitment p2Commitment = commitmentScheme.generateCommitments(p2, x);

			measurement.start();
			if (!commitmentScheme.checkValidityOfPolynomialsProperty(x, p1Commitment, p2Commitment)) {
				throw new RuntimeException("Same polynomials returned false");
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
