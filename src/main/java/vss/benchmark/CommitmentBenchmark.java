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

public class CommitmentBenchmark {
    private static SecureRandom rndGenerator;
    private static int threshold;
    private static BigInteger field;
    private static BigInteger[] shareholders;

    public static void main(String[] args) throws SecretSharingException {
        if (args.length != 5) {
            System.out.println("USAGE: ... vss.benchmark.CommitmentBenchmark " +
                    "<threshold> <num secrets> <warm up iterations> <test iterations> " +
                    "<commitment scheme -> linear|ec_linear|c_ec_linear|dl_kzg>");
            System.exit(-1);
        }
        threshold = Integer.parseInt(args[0]);
        int nSecrets = Integer.parseInt(args[1]);
        int warmUpIterations = Integer.parseInt(args[2]);
        int testIterations = Integer.parseInt(args[3]);
        String commitmentSchemeName = args[4];

        int n = 3 * threshold + 1;

        System.out.println("t = " + threshold);
        System.out.println("n = " + n);
        System.out.println("number of secrets = " + nSecrets);
        System.out.println("commitment scheme = " + commitmentSchemeName);
        System.out.println();

        shareholders = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            BigInteger shareholder = BigInteger.valueOf(i + 1);
            shareholders[i] = shareholder;
        }

        CommitmentScheme commitmentScheme = CommitmentSchemeFactory.createCommitmentScheme(commitmentSchemeName,
				threshold, shareholders);

		field = commitmentScheme.getSubPrimeFieldOrder();
        rndGenerator = new SecureRandom("ola".getBytes());

        System.out.println("Warming up (" + warmUpIterations + " iterations)");
        if (warmUpIterations > 0)
            runTests(warmUpIterations, false, nSecrets, commitmentScheme);
        System.out.println("Running test (" + testIterations + " iterations)");
        if (testIterations > 0)
            runTests(testIterations, true, nSecrets, commitmentScheme);
    }

    private static void runTests(int nTests, boolean printResults, int nSecrets,
                                 CommitmentScheme commitmentScheme) throws SecretSharingException {
		BigInteger num1 = getRandomNumber();
		BigInteger num2 = getRandomNumber();
		BigInteger constant = getRandomNumber();
		BigInteger shareholder = shareholders[0];

        long start, end;
        long[] commitmentCreationTimes = new long[nTests];
        long[] singleVerificationTimes = new long[nTests];
        long[] sumTimes = new long[nTests];
        long[] subtractTimes = new long[nTests];
        long[] sumExtractedTimes = new long[nTests];
        long[] subtractExtractedTimes = new long[nTests];
		long[] addConstant = new long[nTests];
		long[] subtractConstant = new long[nTests];
		long[] multiplyByConstant = new long[nTests];
        for (int nT = 0; nT < nTests; nT++) {
            Polynomial polynomial1 = new Polynomial(field, threshold, num1, rndGenerator);
            Polynomial polynomial2 = new Polynomial(field, threshold, num2, rndGenerator);
            Share share1 = new Share(shareholder, polynomial1.evaluateAt(shareholder));
            Share share2 = new Share(shareholder, polynomial2.evaluateAt(shareholder));

			//Generate commitments
            Commitment commitment1 = commitmentScheme.generateCommitments(polynomial1);
            Commitment commitment2 = commitmentScheme.generateCommitments(polynomial2);
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                commitment1 = commitmentScheme.generateCommitments(polynomial1);
            }
            end = System.nanoTime();
            commitmentCreationTimes[nT] = end - start;

            Commitment extractedCommitment1 = commitmentScheme.extractCommitment(shareholder, commitment1);
            Commitment extractedCommitment2 = commitmentScheme.extractCommitment(shareholder, commitment2);

			//Check share validity
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                commitmentScheme.checkValidityWithoutPreComputation(share1, extractedCommitment1);
                /*if (!commitmentScheme.checkValidityWithoutPreComputation(share, extractedCommitment)) {
                    throw new IllegalStateException("Invalid share");
                }*/
            }
            end = System.nanoTime();
            singleVerificationTimes[nT] = end - start;

			//Add shares and commitments
			Share computedShares = new Share(shareholder, share1.getShare().add(share2.getShare()).mod(field));
			Commitment computedCommitment = null;
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
				computedCommitment = commitmentScheme.sumCommitments(commitment1, commitment2);
            }
            end = System.nanoTime();
            sumTimes[nT] = end - start;
			if (!commitmentScheme.checkValidityWithoutPreComputation(computedShares, computedCommitment)) {
				throw new IllegalStateException("Added shares and commitments do not match");
			}

			//Subtract shares and commitments
			computedShares = new Share(shareholder, share1.getShare().subtract(share2.getShare()).mod(field));
            start = System.nanoTime();
            for (int i = 0; i < nSecrets; i++) {
                computedCommitment = commitmentScheme.subtractCommitments(commitment1, commitment2);
            }
            end = System.nanoTime();
            subtractTimes[nT] = end - start;
			if (!commitmentScheme.checkValidityWithoutPreComputation(computedShares, computedCommitment)) {
				throw new IllegalStateException("Subtracted shares and commitments do not match");
			}

			//Add shares and extracted commitments
			computedShares = new Share(shareholder, share1.getShare().add(share2.getShare()).mod(field));
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                computedCommitment = commitmentScheme.sumCommitments(extractedCommitment1, extractedCommitment2);
            }
            end = System.nanoTime();
            sumExtractedTimes[nT] = end - start;
			if (!commitmentScheme.checkValidityWithoutPreComputation(computedShares, computedCommitment)) {
				throw new IllegalStateException("Added shares and extracted commitments do not match");
			}

			//Subtract shares and extracted commitments
			computedShares = new Share(shareholder, share1.getShare().subtract(share2.getShare()).mod(field));
            start = System.nanoTime();
            for (int i = 0; i < nSecrets; i++) {
                computedCommitment = commitmentScheme.subtractCommitments(extractedCommitment1, extractedCommitment2);
            }
            end = System.nanoTime();
            subtractExtractedTimes[nT] = end - start;
			if (!commitmentScheme.checkValidityWithoutPreComputation(computedShares, computedCommitment)) {
				throw new IllegalStateException("Subtracted shares and extracted commitments do not match");
			}

			//Add a constant
			computedShares = new Share(shareholder, share1.getShare().add(constant).mod(field));
			start = System.nanoTime();
			for (int i = 0; i < nSecrets; i++) {
				computedCommitment = commitmentScheme.addConstant(extractedCommitment1, constant);
			}
			end = System.nanoTime();
			addConstant[nT] = end - start;
			if (!commitmentScheme.checkValidityWithoutPreComputation(computedShares, computedCommitment)) {
				throw new IllegalStateException("Added constant to shares and extracted commitments do not match");
			}

			//Subtract a constant
			computedShares = new Share(shareholder, share1.getShare().subtract(constant).mod(field));
			start = System.nanoTime();
			for (int i = 0; i < nSecrets; i++) {
				computedCommitment = commitmentScheme.subtractConstant(extractedCommitment1, constant);
			}
			end = System.nanoTime();
			subtractConstant[nT] = end - start;
			if (!commitmentScheme.checkValidityWithoutPreComputation(computedShares, computedCommitment)) {
				throw new IllegalStateException("Subtracted constant from shares and extracted commitments do not match");
			}

			//Multiply by a constant
			computedShares =  new Share(shareholder, share1.getShare().multiply(constant).mod(field));
			start = System.nanoTime();
			for (int i = 0; i < nSecrets; i++) {
				computedCommitment = commitmentScheme.multiplyByConstant(extractedCommitment1, constant);
			}
			end = System.nanoTime();
			multiplyByConstant[nT] = end - start;
			if (!commitmentScheme.checkValidityWithoutPreComputation(computedShares, computedCommitment)) {
				throw new IllegalStateException("Multiplied shares and extracted commitments by constant do not match");
			}
        }

        if (printResults) {
            double creationAvg = computeAverage(commitmentCreationTimes);
            double singleVerificationAvg = computeAverage(singleVerificationTimes);
            double sumAvg = computeAverage(sumTimes);
            double subtractAvg = computeAverage(subtractTimes);
            double sumExtractedAvg = computeAverage(sumExtractedTimes);
            double subtractExtractedAvg = computeAverage(subtractExtractedTimes);
			double addConstantAvg = computeAverage(addConstant);
			double subtractConstantAvg = computeAverage(subtractConstant);
			double multiplyByConstantAvg = computeAverage(multiplyByConstant);

            System.out.println("Creation: " + creationAvg + " ms");
            System.out.println("Single verification: " + singleVerificationAvg + " ms");
            System.out.println("Sum: " + sumAvg + " ms");
            System.out.println("Subtract: " + subtractAvg + " ms");
            System.out.println("Sum extracted: " + sumExtractedAvg + " ms");
            System.out.println("Subtract extracted: " + subtractExtractedAvg + " ms");
			System.out.println("Add constant: " + addConstantAvg + " ms");
			System.out.println("Subtract constant: " + subtractConstantAvg + " ms");
			System.out.println("Multiply by constant: " + multiplyByConstantAvg + " ms");
        }
    }

    private static double computeAverage(long[] values) {
        return ((double) Arrays.stream(values).sum() / values.length) / 1_000_000.0;
    }

    private static BigInteger getRandomNumber() {
        int numBits = field.bitLength() - 1;
        BigInteger rndBig = new BigInteger(numBits, rndGenerator);
        if (rndBig.compareTo(BigInteger.ZERO) == 0)
            rndBig = rndBig.add(BigInteger.ONE);
        return rndBig;
    }
}
