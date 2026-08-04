package vss.benchmark;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentSchemeFactory;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @author robin
 */
public class VSSBenchmark {
	private static BigInteger subPrimeField;
	private static final SecureRandom rndGenerator = new SecureRandom();

	public static void main(String[] args) throws SecretSharingException {
		if (args.length != 4) {
			System.out.println("USAGE: ... vss.benchmark.VSSBenchmark <threshold> " +
					"<commitment scheme: linear | ec_linear | c_ec_linear | dl_kzg> " +
					"<warm up iterations> <test iterations>");
			System.exit(-1);
		}

		int threshold = Integer.parseInt(args[0]);
		int n = 3 * threshold + 1;
		String commitmentSchemeType = args[1];
		int warmUpIterations = Integer.parseInt(args[2]);
		int testIterations = Integer.parseInt(args[3]);

		BigInteger[] shareholders = new BigInteger[n];
		for (int i = 0; i < shareholders.length; i++) {
			shareholders[i] = BigInteger.valueOf(i + 1);
		}

		System.out.println("t = " + threshold);
		System.out.println("n = " + n);

		CommitmentScheme commitmentScheme = CommitmentSchemeFactory.createCommitmentScheme(commitmentSchemeType,
				threshold, shareholders);

		subPrimeField = commitmentScheme.getSubPrimeFieldOrder();
		System.out.println("Prime field order: " + commitmentScheme.getPrimeFieldOrder().toString(16));
		System.out.println("Sub-prime field order: " + commitmentScheme.getSubPrimeFieldOrder().toString(16));
		System.out.println("Warming up (" + warmUpIterations + " iterations)");
		if (warmUpIterations > 0)
			runTests(warmUpIterations, false, threshold, shareholders, commitmentScheme);
		System.out.println("Running test (" + testIterations + " iterations)");
		if (testIterations > 0)
			runTests(testIterations, true, threshold, shareholders, commitmentScheme);
	}

	private static void runTests(int nTests, boolean printResults, int t, BigInteger[] shareholders,
	                             CommitmentScheme commitmentScheme) throws SecretSharingException {

		long[] secretSharingTimes = new long[nTests];
		long[] commitmentGenerationTimes = new long[nTests];
		long[] commitmentVerificationTimes = new long[nTests];
		long[] combineTimes = new long[nTests];
		long start, end;
		for (int nT = 0; nT < nTests; nT++) {
			long secretSharingTime;
			long commitmentGenerationTime;
			long commitmentVerificationTime;
			long combineTime;

			BigInteger rndNumber = getRandomNumber(subPrimeField);

			start = System.nanoTime();
			Polynomial polynomial = new Polynomial(subPrimeField, t, rndNumber, rndGenerator);
			Share[] shares = new Share[shareholders.length];
			for (int i = 0; i < shareholders.length; i++) {
				BigInteger shareholder = shareholders[i];
				shares[i] = new Share(shareholder, polynomial.evaluateAt(shareholder));
			}
			end = System.nanoTime();
			secretSharingTime = end - start;

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

			Share[] minNumberOfShares = new Share[t + 1];
			System.arraycopy(shares, 0, minNumberOfShares, 0, t + 1);

			start = System.nanoTime();
			Polynomial reconstructedPolynomial = new Polynomial(subPrimeField, minNumberOfShares);
			BigInteger reconstructedSecret = reconstructedPolynomial.evaluateAt(BigInteger.ZERO);
			if (!reconstructedSecret.equals(rndNumber)) {
				throw new IllegalStateException("Reconstructed secret does not match original secret");
			}
			end = System.nanoTime();
			combineTime = end - start;
			secretSharingTimes[nT] = secretSharingTime;
			commitmentGenerationTimes[nT] = commitmentGenerationTime;
			commitmentVerificationTimes[nT] = commitmentVerificationTime;
			combineTimes[nT] = combineTime;
		}

		if (printResults) {
			double secretSharingTime = computeAverage(secretSharingTimes);
			double commitmentGenerationTime = computeAverage(commitmentGenerationTimes);
			double commitmentVerificationTime = computeAverage(commitmentVerificationTimes);
			double combineTime = computeAverage(combineTimes);

			System.out.printf("Secret sharing: %.6f ms\n", secretSharingTime);
			System.out.printf("Commitment generation: %.6f ms\n", commitmentGenerationTime);
			System.out.printf("Commitment verification (1 share): %.6f ms\n", commitmentVerificationTime);
			System.out.printf("Combine (t+1 shares): %.6f ms\n", combineTime);
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
