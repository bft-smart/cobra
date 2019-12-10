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
import java.util.*;

import static confidential.Configuration.*;

/**
 * @author Robin
 */
public class RecoveryBenchmark {
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
            System.out.println("USAGE: ... confidential.benchmark.RecoveryBenchmark " +
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

        n = 3 * threshold + 1;

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
        int recoveryShareholderIndex = 0;
        BigInteger field = vssFacade.getField();
        CommitmentScheme commitmentScheme = vssFacade.getCommitmentScheme();
        Measurement mRecoveryShareGeneration = new Measurement(nTests);
        Measurement mSharesRecovery = new Measurement(nTests);
        Measurement mCommitmentsRecovery = new Measurement(nTests);
        Measurement mSharesVerification = new Measurement(nTests);

        Set<BigInteger> corruptedServers = new HashSet<>(threshold);

        Polynomial recoveryPolynomial =
                createRecoveryPolynomialFor(recoveryShareholderIndex, vssFacade);

        Commitment tempRecoveryCommitment =
                commitmentScheme.generateCommitments(recoveryPolynomial);
        Map<BigInteger, Commitment> temp = new HashMap<>(n - 1);
        //removing recovering shareholder commitment
        for (int i = 0; i < n; i++) {
            if (i == recoveryShareholderIndex)
                continue;
            temp.put(shareholders[i],
                    commitmentScheme.extractCommitment(shareholders[i], tempRecoveryCommitment));
        }
        Commitment recoveryCommitment = commitmentScheme.combineCommitments(temp);
        BigInteger[] recoveryPoints = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            recoveryPoints[i] = recoveryPolynomial.evaluateAt(shareholders[i]);
        }

        byte[] secret = new byte[1024];
        rndGenerator.nextBytes(secret);
        //creating shares
        PrivatePublishedShares privateShares = vssFacade.share(secret, keys);
        VerifiableShare[] verifiableShares = new VerifiableShare[n];
        for (int i = 0; i < n; i++) {
            verifiableShares[i] = vssFacade.extractShare(privateShares, shareholders[i],
                    keys.get(shareholders[i]));
        }

        for (int nT = 0; nT < nTests; nT++) {
            corruptedServers.clear();

            for (int nS = 0; nS < nSecrets; nS++) {
                //creating recovery shares
                Share[] recoveryShares = new Share[n - 1];
                for (int i = 0, j = 0; i < n; i++) {
                    VerifiableShare vs = verifiableShares[i];
                    if (i == recoveryShareholderIndex) {
                        mRecoveryShareGeneration.start();
                        new Share(vs.getShare().getShareholder(),
                                vs.getShare().getShare().add(recoveryPoints[i]).mod(field));
                        mRecoveryShareGeneration.stop();
                        continue;
                    }
                    recoveryShares[j++] = new Share(vs.getShare().getShareholder(),
                            vs.getShare().getShare().add(recoveryPoints[i]).mod(field));
                }

                Map<BigInteger, Commitment> recoveryCommitments = new HashMap<>(n - 1);
                for (int i = 0; i < n; i++) {
                    if (i == recoveryShareholderIndex)
                        continue;
                    recoveryCommitments.put(shareholders[i],
                            verifiableShares[i].getCommitments());
                }

                //recovering a share
                mCommitmentsRecovery.start();
                Commitment recoveredCommitment =
                        commitmentScheme.recoverCommitment(shareholders[recoveryShareholderIndex], recoveryCommitments);
                mCommitmentsRecovery.stop();

                mSharesRecovery.start();
                Share[] recoveringShares =
                        new Share[threshold + (corruptedServers.size() < threshold ? 2
                                : 1)];

                Map<BigInteger, Share> allRecoveringShares = new HashMap<>();
                for (int i = 0, j = 0; i < recoveryShares.length; i++) {
                    Share share = recoveryShares[i];
                    if (j < recoveringShares.length && !corruptedServers.contains(share.getShareholder()))
                        recoveringShares[j++] = share;
                    allRecoveringShares.put(share.getShareholder(), share);
                }

                Polynomial polynomial = new Polynomial(field, recoveringShares);
                BigInteger shareNumber;
                mSharesRecovery.stop();

                if (polynomial.getDegree() != threshold) {
                    mSharesVerification.start();
                    recoveringShares = new Share[threshold + 1];
                    Commitment combinedCommitment =
                            commitmentScheme.combineCommitments(recoveryCommitments);
                    Commitment verificationCommitment =
                            commitmentScheme.sumCommitments(recoveryCommitment,
                                    combinedCommitment);
                    commitmentScheme.startVerification(verificationCommitment);
                    int j = 0;
                    for (Map.Entry<BigInteger, Share> entry : allRecoveringShares.entrySet()) {
                        if (commitmentScheme.checkValidity(entry.getValue(), verificationCommitment))
                            recoveringShares[j++] = entry.getValue();
                        else {
                            corruptedServers.add(entry.getValue().getShareholder());
                        }
                    }
                    commitmentScheme.endVerification();
                    mSharesVerification.stop();
                    mSharesRecovery.start();
                    shareNumber =
                            vssFacade.getInterpolationStrategy().interpolateAt(shareholders[recoveryShareholderIndex], recoveringShares);
                } else {
                    mSharesRecovery.start();
                    shareNumber =
                            polynomial.evaluateAt(shareholders[recoveryShareholderIndex]);
                }

                Share recoveredShare = new Share(shareholders[recoveryShareholderIndex], shareNumber);
                verifiableShares[recoveryShareholderIndex] =
                        new VerifiableShare(recoveredShare, recoveredCommitment,
                                verifiableShares[(recoveryShareholderIndex + 1) % n].getSharedData());
                mSharesRecovery.stop();

                if (verifyCorrectness) {
                    Share[] shares = new Share[n];
                    Map<BigInteger, Commitment> commitments = new HashMap<>(n);
                    byte[] sharedData = null;
                    for (int i = 0; i < n; i++) {
                        VerifiableShare vs = verifiableShares[i];
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

        double recoveryShareGeneration =
                mRecoveryShareGeneration.getAverageInMillis(nDecimals);
        double sharesRecovery = mSharesRecovery.getAverageInMillis(nDecimals);
        double commitmentsRecovery = mCommitmentsRecovery.getAverageInMillis(nDecimals);
        double sharesVerification = mSharesVerification.getAverageInMillis(nDecimals);

        if (printResults) {
            System.out.println("Recovery share generation: " + recoveryShareGeneration +  " ms");
            System.out.println("Share recovery: " + sharesRecovery + " ms");
            System.out.println("Commitment recovery: " + commitmentsRecovery + " ms");
            System.out.println("Shares verification: " + sharesVerification + " ms");
            System.out.println("Recovery total: " + (recoveryShareGeneration + sharesRecovery
                    + commitmentsRecovery + sharesVerification) + " ms");
        }
    }

    private static Polynomial createRecoveryPolynomialFor(int recoveryShareholderIndex, VSSFacade vssFacade) {
        Polynomial tempPolynomial = new Polynomial(vssFacade.getField(), threshold,
                BigInteger.ZERO, rndGenerator);
        BigInteger independentTerm =
                tempPolynomial.evaluateAt(shareholders[recoveryShareholderIndex]).negate();
        BigInteger[] tempCoefficients = tempPolynomial.getCoefficients();
        BigInteger[] coefficients = Arrays.copyOfRange(tempCoefficients,
                tempCoefficients.length - tempPolynomial.getDegree() - 1,
                tempCoefficients.length - 1);

        return new Polynomial(vssFacade.getField(), independentTerm, coefficients);
    }
}
