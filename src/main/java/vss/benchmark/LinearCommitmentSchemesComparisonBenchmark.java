package vss.benchmark;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.ellipticCurve.EllipticCurveCommitmentScheme;
import vss.commitment.linear.FeldmanCommitmentScheme;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @author robin
 */
public class LinearCommitmentSchemesComparisonBenchmark {
	private static final SecureRandom rndGenerator = new SecureRandom();

	public static void main(String[] args) {
		if (args.length != 3) {
			System.out.println("USAGE: ... vss.benchmark.LinearCommitmentSchemesComparisonBenchmark <threshold> " +
					"<warm up iterations> <test iterations>");
			System.exit(-1);
		}

		int threshold = Integer.parseInt(args[0]);
		int n = 3 * threshold + 1;
		int warmUpIterations = Integer.parseInt(args[1]);
		int testIterations = Integer.parseInt(args[2]);

		System.out.println("t = " + threshold);
		System.out.println("n = " + n);

		BigInteger prime = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
		BigInteger order = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
		BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
		BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
		byte[] compressedGenerator = new BigInteger("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16).toByteArray();

		BigInteger feldmanPrime = new BigInteger("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16);
		BigInteger feldmanGenerator = new BigInteger("3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659", 16);
		BigInteger feldmanField = new BigInteger("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16);


		EllipticCurveCommitmentScheme ellipticCurveCommitmentScheme = new EllipticCurveCommitmentScheme(
				prime,
				order,
				a,
				b,
				compressedGenerator
		);

		FeldmanCommitmentScheme feldmanCommitmentScheme = new FeldmanCommitmentScheme(
				feldmanPrime,
				feldmanGenerator
		);

		System.out.println("\n====== Linear commitment scheme using integers ======");
		System.out.println("Warming up (" + warmUpIterations + " iterations)");
		if (warmUpIterations > 0)
			runTests(warmUpIterations, false, threshold, feldmanField, feldmanCommitmentScheme);
		System.out.println("Running test (" + testIterations + " iterations)");
		if (testIterations > 0)
			runTests(testIterations, true, threshold, feldmanField, feldmanCommitmentScheme);

		System.out.println("\n====== Linear commitment scheme using elliptic curve ======");
		System.out.println("Warming up (" + warmUpIterations + " iterations)");
		if (warmUpIterations > 0)
			runTests(warmUpIterations, false, threshold, order, ellipticCurveCommitmentScheme);
		System.out.println("Running test (" + testIterations + " iterations)");
		if (testIterations > 0)
			runTests(testIterations, true, threshold, order, ellipticCurveCommitmentScheme);
	}

	private static void runTests(int nTests, boolean printResults, int t, BigInteger field,
								 CommitmentScheme commitmentScheme) {

		BigInteger[] shareholders = new BigInteger[t + 1];
		for (int i = 0; i < shareholders.length; i++) {
			shareholders[i] = BigInteger.valueOf(i + 1);
		}

		long[] commitmentGenerationTimes = new long[nTests];
		long[] commitmentVerificationTimes = new long[nTests];
		long start, end;
		for (int nT = 0; nT < nTests; nT++) {
			long commitmentGenerationTime;
			long commitmentVerificationTime;

			BigInteger rndNumber = getRandomNumber(field);

			Polynomial polynomial = new Polynomial(field, t, rndNumber, rndGenerator);
			Share[] shares = new Share[shareholders.length];
			for (int i = 0; i < shareholders.length; i++) {
				BigInteger shareholder = shareholders[i];
				shares[i] = new Share(shareholder, polynomial.evaluateAt(shareholder));
			}

			start = System.nanoTime();
			Commitment commitment = commitmentScheme.generateCommitments(polynomial);
			end = System.nanoTime();
			commitmentGenerationTime = end - start;

			start = System.nanoTime();
			boolean isValid = commitmentScheme.checkValidityWithoutPreComputation(shares[0], commitment);
			end = System.nanoTime();
			commitmentVerificationTime = end - start;
			if (!isValid)
				throw new IllegalStateException("Commitment is invalid");
			commitmentGenerationTimes[nT] = commitmentGenerationTime;
			commitmentVerificationTimes[nT] = commitmentVerificationTime;
		}

		if (printResults) {
			double commitmentGenerationTime = computeAverage(commitmentGenerationTimes);
			double commitmentVerificationTime = computeAverage(commitmentVerificationTimes);

			System.out.printf("Commitment generation: %.6f ms\n", commitmentGenerationTime);
			System.out.printf("Commitment verification (1 share): %.6f ms\n", commitmentVerificationTime);
		}
	}

	private static double computeAverage(long[] values) {
		return (double) Arrays.stream(values).sum() / (double)values.length / 1000000.0D;
	}

	private static BigInteger getRandomNumber(BigInteger field) {
		BigInteger rndBig = new BigInteger(field.bitLength() - 1, rndGenerator);
		if (rndBig.compareTo(BigInteger.ZERO) == 0) {
			rndBig = rndBig.add(BigInteger.ONE);
		}

		return rndBig;
	}
}
