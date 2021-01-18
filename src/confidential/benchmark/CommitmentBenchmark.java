package confidential.benchmark;

import confidential.Configuration;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.constant.KateCommitmentScheme;
import vss.commitment.linear.FeldmanCommitmentScheme;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;

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
            System.out.println("USAGE: ... confidential.benchmark.CommitmentBenchmark " +
                    "<threshold> <num secrets> <warm up iterations> <test iterations> " +
                    "<commitment scheme -> linear|constant>");
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

        Configuration configuration = Configuration.getInstance();
        field = new BigInteger(configuration.getSubPrimeField(), 16);
        CommitmentScheme commitmentScheme;
        if (commitmentSchemeName.equals("linear")) {
            BigInteger p = new BigInteger(configuration.getPrimeField(), 16);
            BigInteger generator = new BigInteger(configuration.getGenerator(), 16);
            commitmentScheme = new FeldmanCommitmentScheme(p, generator);
        } else if (commitmentSchemeName.equals("constant")) {
            commitmentScheme = new KateCommitmentScheme(threshold, shareholders);
        } else
            throw new IllegalStateException("Commitment scheme is unknown");

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
        BigInteger num = getRandomNumber();
        BigInteger shareholder = shareholders[0];
        Polynomial p1 = new Polynomial(field, threshold, num, rndGenerator);
        Polynomial p2 = new Polynomial(field, threshold, num, rndGenerator);
        Commitment c1 = commitmentScheme.generateCommitments(p1);
        Commitment c2 = commitmentScheme.generateCommitments(p2);

        Commitment c1Extracted = commitmentScheme.extractCommitment(shareholder, c1);
        Commitment c2Extracted = commitmentScheme.extractCommitment(shareholder, c2);

        long start, end;
        long[] sumTimes = new long[nTests];
        long[] subtractTimes = new long[nTests];
        long[] sumExtractedTimes = new long[nTests];
        long[] subtractExtractedTimes = new long[nTests];
        for (int nT = 0; nT < nTests; nT++) {
            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                commitmentScheme.sumCommitments(c1, c2);
            }
            end = System.nanoTime();
            sumTimes[nT] = end - start;

            start = System.nanoTime();
            for (int i = 0; i < nSecrets; i++) {
                commitmentScheme.subtractCommitments(c1, c2);
            }
            end = System.nanoTime();
            subtractTimes[nT] = end - start;

            start = System.nanoTime();
            for (int nS = 0; nS < nSecrets; nS++) {
                commitmentScheme.sumCommitments(c1Extracted, c2Extracted);
            }
            end = System.nanoTime();
            sumExtractedTimes[nT] = end - start;

            start = System.nanoTime();
            for (int i = 0; i < nSecrets; i++) {
                commitmentScheme.subtractCommitments(c1Extracted, c2Extracted);
            }
            end = System.nanoTime();
            subtractExtractedTimes[nT] = end - start;
        }

        if (printResults) {
            double sumAvg = computeAverage(sumTimes);
            double subtractAvg = computeAverage(subtractTimes);
            double sumExtractedAvg = computeAverage(sumExtractedTimes);
            double subtractExtractedAvg = computeAverage(subtractExtractedTimes);

            System.out.println("Sum: " + sumAvg + " ms");
            System.out.println("Subtract: " + subtractAvg + " ms");
            System.out.println("Sum extracted: " + sumExtractedAvg + " ms");
            System.out.println("Subtract extracted: " + subtractExtractedAvg + " ms");
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
