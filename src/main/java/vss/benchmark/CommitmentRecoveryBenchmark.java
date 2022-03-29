package vss.benchmark;

import vss.Constants;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.constant.ConstantCommitment;
import vss.commitment.constant.ShareCommitment;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.polynomial.Polynomial;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

/**
 * @author Robin
 */
public class CommitmentRecoveryBenchmark {
    private static SecureRandom rndGenerator;
    private static int threshold;
    private static int n;
    private static BigInteger[] shareholders;

    public static void main(String[] args) throws SecretSharingException {
        if (args.length != 6) {
            System.out.println("USAGE: ... vss.benchmark.CommitmentRecoveryBenchmark <threshold> " +
                    "<num secrets> <warm up iterations> <test iterations> " +
                    "<min number of faulty shareholders> <max number of faulty shareholders");
            System.exit(-1);
        }

        threshold = Integer.parseInt(args[0]);
        n = 3 * threshold + 1;
        int quorum = n - threshold;
        int nSecrets = Integer.parseInt(args[1]);
        int warmUpIterations = Integer.parseInt(args[2]);
        int testIterations = Integer.parseInt(args[3]);
        int minFaultyCommitments = Integer.parseInt(args[4]);
        int maxFaultyCommitments = Integer.parseInt(args[5]);

        if (minFaultyCommitments < 0 || minFaultyCommitments > threshold || minFaultyCommitments > maxFaultyCommitments)
            throw new IllegalArgumentException("min number of faulty shareholders is out of range");

        if (maxFaultyCommitments > threshold)
            throw new IllegalArgumentException("max number of faulty shareholders is out of range");

        System.out.println("t = " + threshold);
        System.out.println("n = " + n);
        System.out.println("quorum = " + quorum);
        System.out.println("number of secrets = " + nSecrets);
        System.out.println();


        rndGenerator = new SecureRandom("ola".getBytes());
        shareholders = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            shareholders[i] = BigInteger.valueOf(i + 1);
        }

        Properties properties = new Properties();
        properties.put(Constants.TAG_THRESHOLD, String.valueOf(threshold));
        properties.put(Constants.TAG_DATA_ENCRYPTION_ALGORITHM, "AES");
        properties.put(Constants.TAG_COMMITMENT_SCHEME, Constants.VALUE_KATE_SCHEME);

        VSSFacade vssFacade = new VSSFacade(properties, shareholders);
        System.out.println("Warming up (" + warmUpIterations + " iterations)");
        if (warmUpIterations > 0)
            runTests(warmUpIterations, false, vssFacade, minFaultyCommitments,
                    maxFaultyCommitments, quorum,
                    nSecrets);
        System.out.println("Running test (" + testIterations + " iterations)");
        if (testIterations > 0)
            runTests(testIterations, true, vssFacade, minFaultyCommitments, maxFaultyCommitments,
                    quorum, nSecrets);

    }

    private static void runTests(int nTests, boolean printResults,
                                 VSSFacade vss, int minFaultyC,
                                 int maxFaultyC, int quorum, int nSecrets) {
        for (int faultyC = minFaultyC; faultyC <= maxFaultyC; faultyC++) {
            if (printResults)
                System.out.println("============= " + faultyC + " faulty commitments" +
                        " =============");
            BigInteger field = vss.getField();
            CommitmentScheme commitmentScheme = vss.getCommitmentScheme();
            BigInteger secret = new BigInteger(field.bitLength() - 2, rndGenerator);
            Polynomial secretPolynomial = new Polynomial(field, threshold, secret,
                    rndGenerator);
            BigInteger recoveryShareholder = shareholders[0];
            for (int nT = 0; nT < nTests; nT++) {
                Set<BigInteger> corruptedShareholders = new HashSet<>(threshold);
                for (int nS = 0; nS < nSecrets; nS++) {
                    Commitment commitment =
                            commitmentScheme.generateCommitments(secretPolynomial);
                    Map<BigInteger, Commitment> commitments = new HashMap<>(n);

                    for (int i = 0; i < n; i++) {
                        BigInteger shareholder = shareholders[i];
                        if (shareholder.equals(recoveryShareholder))
                            continue;
                        if (corruptedShareholders.contains(shareholder))
                            continue;
                        commitments.put(shareholder,
                                commitmentScheme.extractCommitment(shareholder,
                                        commitment));
                        if (commitments.size() == threshold + 1)
                            break;
                    }

                    //corrupting witnesses
                    BigInteger corruptedShareholder;
                    if (corruptedShareholders.size() < faultyC) {
                        corruptedShareholder = commitments.keySet().iterator().next();
                        System.out.println("Corrupting shareholder: " + corruptedShareholder);
                        byte[] corruptedWitness = new byte[49];
                        rndGenerator.nextBytes(corruptedWitness);
                        commitments.put(corruptedShareholder,
                                new ShareCommitment(((ConstantCommitment)commitment).getCommitment(), corruptedWitness));
                        corruptedShareholders.add(corruptedShareholder);
                    }

                    Commitment recoveredCommitment = null;
                    try {
                        recoveredCommitment = commitmentScheme.recoverCommitment(recoveryShareholder,
                                commitments);
                    } catch (SecretSharingException e) {
                        Map<BigInteger, Commitment> validCommitments = new HashMap<>(threshold);
                        for (Map.Entry<BigInteger, Commitment> entry : commitments.entrySet()) {
                            if (corruptedShareholders.contains(entry.getKey()))
                                continue;
                            validCommitments.put(entry.getKey(), entry.getValue());
                            if (validCommitments.size() == threshold)
                                break;
                        }
                        try {
                            recoveredCommitment =
                                    commitmentScheme.recoverCommitment(recoveryShareholder,
                                            validCommitments);
                        } catch (SecretSharingException ex) {
                            System.err.println("This should not happen");
                            System.exit(-1);
                        }
                    }

                    if (!recoveredCommitment.equals(commitmentScheme.extractCommitment(recoveryShareholder, commitment)))
                        throw new IllegalStateException("Commitments are different");
                }
            }
        }
    }
}
