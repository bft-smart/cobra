package confidential.benchmark;

import confidential.Configuration;
import vss.Constants;
import vss.benchmark.Measurement;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.polynomial.Polynomial;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.PrivatePublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * @author Robin
 */
public class RenewalBenchmark {
    private static final BigInteger keyNumber = new BigInteger("937810634060551071826485204471949219646466658841719067506");
    private static SecureRandom rndGenerator;
    private static final int nDecimals = 4;
    private static int threshold;
    private static BigInteger[] shareholders;
    private static int n;
    private static Map<BigInteger, Key> keys;
    private static boolean verifyCorrectness;

    public static void main(String[] args) throws SecretSharingException {
        if (args.length != 6) {
            System.out.println("USAGE: ... confidential.benchmark.RenewalBenchmark " +
                    "<threshold> <num secrets> <warm up iterations> <test iterations> " +
                    "<verify correctness> <commitment scheme -> linear|constant>");
            System.exit(-1);
        }

        threshold = Integer.parseInt(args[0]);
        int nSecrets = Integer.parseInt(args[1]);
        int warmUpIterations = Integer.parseInt(args[2]);
        int testIterations = Integer.parseInt(args[3]);
        verifyCorrectness = Boolean.parseBoolean(args[4]);
        String commitmentSchemeName = args[5];


        n = threshold + 2;

        System.out.println("t = " + threshold);
        System.out.println("n = " + n);
        System.out.println("number of secrets = " + nSecrets);
        System.out.println("commitment scheme = " + commitmentSchemeName);
        System.out.println();

        shareholders = new BigInteger[n];
        keys = new HashMap<>(n);
        for (int i = 0; i < n; i++) {
            BigInteger shareholder = BigInteger.valueOf(i + 1);
            shareholders[i] = shareholder;
            keys.put(shareholder, new SecretKeySpec(keyNumber.toByteArray(), "AES"));
        }

        Configuration configuration = Configuration.getInstance();

        Properties properties = new Properties();
        properties.put(Constants.TAG_THRESHOLD, String.valueOf(threshold));
        properties.put(Constants.TAG_DATA_ENCRYPTION_ALGORITHM, configuration.getDataEncryptionAlgorithm());
        properties.put(Constants.TAG_SHARE_ENCRYPTION_ALGORITHM, configuration.getShareEncryptionAlgorithm());
        properties.put(Constants.TAG_PRIME_FIELD, configuration.getPrimeField());
        properties.put(Constants.TAG_SUB_FIELD, configuration.getSubPrimeField());
        properties.put(Constants.TAG_GENERATOR, configuration.getGenerator());

        if (commitmentSchemeName.equals("linear")) {
            properties.put(Constants.TAG_COMMITMENT_SCHEME, Constants.VALUE_FELDMAN_SCHEME);
        } else if (commitmentSchemeName.equals("constant")) {
            properties.put(Constants.TAG_COMMITMENT_SCHEME, Constants.VALUE_KATE_SCHEME);
        } else
            throw new IllegalStateException("Commitment scheme is unknown");

        rndGenerator = new SecureRandom("ola".getBytes());
        VSSFacade vssFacade = new VSSFacade(properties, shareholders);

        System.out.println("Warming up (" + warmUpIterations + " iterations)");
        if (warmUpIterations > 0)
            runTests(warmUpIterations, false, nSecrets, vssFacade);
        System.out.println("Running test (" + testIterations + " iterations)");
        if (testIterations > 0)
            runTests(testIterations, true, nSecrets, vssFacade);
    }

    private static void runTests(int nTests, boolean printResults, int nSecrets,
                                 VSSFacade vssFacade) throws SecretSharingException {
        BigInteger field = vssFacade.getField();
        CommitmentScheme commitmentScheme = vssFacade.getCommitmentScheme();
        Measurement mSharesRenewal = new Measurement(nTests);
        Measurement mCommitmentsRenewal = new Measurement(nTests);

        Polynomial renewalPolynomial = new Polynomial(field, threshold,
                BigInteger.ZERO, rndGenerator);

        Commitment[] renewalCommitments = new Commitment[n];
        Commitment renewalCommitment =
                commitmentScheme.generateCommitments(renewalPolynomial);
        for (int i = 0; i < n; i++) {
            renewalCommitments[i] =
                    commitmentScheme.extractCommitment(shareholders[i],
                            renewalCommitment);
        }

        BigInteger[] renewalPoints = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            renewalPoints[i] = renewalPolynomial.evaluateAt(shareholders[i]);
        }

        byte[] secret = new byte[1024];
        rndGenerator.nextBytes(secret);
        PrivatePublishedShares privateShares = vssFacade.share(secret, keys);

        for (int nT = 0; nT < nTests; nT++) {
            for (int nS = 0; nS < nSecrets; nS++) {
                VerifiableShare[] verifiableShares = new VerifiableShare[n];
                for (int i = 0; i < n; i++) {
                    verifiableShares[i] = vssFacade.extractShare(privateShares, shareholders[i],
                            keys.get(shareholders[i]));
                }

                mSharesRenewal.start();
                VerifiableShare vs = verifiableShares[0];
                vs.getShare().setShare(vs.getShare().getShare().add(renewalPoints[0]).mod(field));
                mSharesRenewal.stop();

                mCommitmentsRenewal.start();
                Commitment renewedCommitment =
                        commitmentScheme.sumCommitments(vs.getCommitments(),
                                renewalCommitments[0]);
                vs.setCommitments(renewedCommitment);
                mCommitmentsRenewal.stop();

                for (int i = 1; i < n; i++) {
                    vs = verifiableShares[i];
                    vs.getShare().setShare(vs.getShare().getShare().add(renewalPoints[i]).mod(field));
                    renewedCommitment =
                            commitmentScheme.sumCommitments(vs.getCommitments(),
                                    renewalCommitments[0]);
                    vs.setCommitments(renewedCommitment);
                }

                if (verifyCorrectness) {
                    Share[] shares = new Share[n];
                    Map<BigInteger, Commitment> commitments = new HashMap<>(n);
                    byte[] sharedData = null;
                    for (int i = 0; i < n; i++) {
                        vs = verifiableShares[i];
                        shares[i] = vs.getShare();
                        commitments.put(vs.getShare().getShareholder(), vs.getCommitments());
                        sharedData = vs.getSharedData();
                    }
                    Commitment commitment = commitmentScheme.combineCommitments(commitments);
                    OpenPublishedShares openShares = new OpenPublishedShares(shares,
                            commitment, sharedData);
                    byte[] recoveredSecret = vssFacade.combine(openShares);
                    if (!Arrays.equals(secret, recoveredSecret))
                        throw new IllegalStateException("Secret is different");
                }
            }
        }

        double shareRenewal = mSharesRenewal.getAverageInMillis(nDecimals);
        double commitmentsRenewal = mCommitmentsRenewal.getAverageInMillis(nDecimals);

        if (printResults) {
            System.out.println("Share renewal: " + shareRenewal + " ms");
            System.out.println("Commitments renewal: " + commitmentsRenewal + " ms");
            System.out.println("Renewal total: " + (shareRenewal + commitmentsRenewal) + " ms");
        }
    }
}
