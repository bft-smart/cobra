package vss.benchmark;

import vss.commitment.Commitment;
import vss.commitment.ellipticCurve.EllipticCurveCommitmentScheme;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @author robin
 */
public class EllipticCurveCommitmentBenchmark {
	private static BigInteger field;
	private static final SecureRandom rndGenerator = new SecureRandom();

	public static void main(String[] args) {
		if (args.length != 3) {
			System.out.println("USAGE: ... vss.benchmark.EllipticCurveCommitmentBenchmark <threshold> " +
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

		field = order;

		EllipticCurveCommitmentScheme commitmentScheme = new EllipticCurveCommitmentScheme(
				prime,
				order,
				a,
				b,
				compressedGenerator
		);

		System.out.println("Warming up (" + warmUpIterations + " iterations)");
		if (warmUpIterations > 0)
			runTests(warmUpIterations, false, threshold, n, commitmentScheme);
		System.out.println("Running test (" + testIterations + " iterations)");
		if (testIterations > 0)
			runTests(testIterations, true, threshold, n, commitmentScheme);
	}

	private static void runTests(int nTests, boolean printResults, int t, int n,
								 EllipticCurveCommitmentScheme commitmentScheme) {

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
