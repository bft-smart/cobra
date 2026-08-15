package vss.benchmark;

import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentSchemeFactory;
import vss.facade.SecretSharingException;
import vss.interpolation.InterpolationStrategy;
import vss.interpolation.LagrangeInterpolation;
import vss.polynomial.Polynomial;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.*;

public class VSSBenchmark {
    private static final int nDecimals = 4;
    private static BigInteger field;
    private static Map<Integer, BigInteger> shareholders;
    private static final String dataEncryptionAlgorithm = "AES";
    private static Cipher dataCipher;
    private static SecureRandom rndGenerator;
    private static CommitmentScheme commitmentScheme;
    private static InterpolationStrategy interpolationStrategy;
    private static Set<BigInteger> corruptedShareholders;
    private static Measurement mShareGeneration;
    private static Measurement mCommitmentsGeneration;
    private static Measurement mShareValidation;
    private static Measurement mSharesCombine;
    private static int threshold;
    private static MessageDigest messageDigest;

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, SecretSharingException {
        if (args.length != 8) {
            System.out.println("USAGE: ... vss.benchmark.LinearVSSBenchmark " +
                    "<threshold> " +
                    "<num secrets> <secret size> <warm up iterations> <test iterations> " +
                    "<min number of faulty shareholders> <max number of faulty shareholders> " +
					"<commitment scheme type: linear|ec_linear|c_ec_linear|dl_kzg|ped_kzg>");
            System.exit(-1);
        }

        threshold = Integer.parseInt(args[0]);
        int n = 3 * threshold + 1;
        int quorum = 2 * threshold + 1;
        int nSecrets = Integer.parseInt(args[1]);
        int secretSize = Integer.parseInt(args[2]);
        int warmUpIterations = Integer.parseInt(args[3]);
        int nTests = Integer.parseInt(args[4]);
        int minFaultyShares = Integer.parseInt(args[5]);
        int maxFaultyShares = Integer.parseInt(args[6]);
        String commitmentSchemeType = args[7];

        if (minFaultyShares < 0 || minFaultyShares > threshold || minFaultyShares > maxFaultyShares)
            throw new IllegalArgumentException("min number of faulty shareholders is out of range");

        if (maxFaultyShares > threshold)
            throw new IllegalArgumentException("max number of faulty shareholders is out of range");


		System.out.println("t = " + threshold);
		System.out.println("n = " + n);
		System.out.println("quorum = " + quorum);
		System.out.println("number of secrets = " + nSecrets);
		System.out.println("secret size = " + secretSize);
		System.out.println();

		shareholders = new HashMap<>(n);
		BigInteger[] shareholdersArray = new BigInteger[n];
		for (int i = 0; i < n; i++) {
			shareholders.put(i, BigInteger.valueOf(i + 1));
			shareholdersArray[i] = BigInteger.valueOf(i + 1);
		}

		rndGenerator = new SecureRandom("ola".getBytes());
		dataCipher = Cipher.getInstance("AES");
		commitmentScheme = CommitmentSchemeFactory.createCommitmentScheme(commitmentSchemeType, threshold, shareholdersArray);
		field = commitmentScheme.getSubPrimeFieldOrder();
		interpolationStrategy = new LagrangeInterpolation(field);
		messageDigest = MessageDigest.getInstance("SHA-256");
		corruptedShareholders = new HashSet<>();

        System.out.println("Warming up (" + warmUpIterations + " iterations)");
        if (warmUpIterations > 0)
            runTests(warmUpIterations, false, minFaultyShares, maxFaultyShares, quorum,
                    nSecrets, secretSize);
        System.out.println("Running test (" + nTests + " iterations)");
        if (nTests > 0)
            runTests(nTests, true, minFaultyShares, maxFaultyShares,
                    quorum, nSecrets, secretSize);
    }

    private static void runTests(int nTests, boolean printResults, int minFaultyShares,
                                 int maxFaultyShares, int quorum, int nSecrets, int secretSize) throws SecretSharingException {
        Random rnd = new Random();
        for (int faultyShares = minFaultyShares; faultyShares <= maxFaultyShares; faultyShares++) {
            if (printResults) {
                System.out.println("============= first " + faultyShares + " faulty shares =============");
            }
            mShareGeneration = new Measurement(nTests);
            mCommitmentsGeneration = new Measurement(nTests);
            mShareValidation = new Measurement(nTests);
            mSharesCombine = new Measurement(nTests);

            for (int tn = 0; tn < nTests; tn++) {
                corruptedShareholders.clear();
                Set<BigInteger> corruptedShareholders = new HashSet<>();
                for (int j = 0; j < nSecrets; j++) {
                    byte[] secret = new byte[secretSize];
                    rnd.nextBytes(secret);
                    OpenPublishedShares privateShares = share(secret);

                    Share[] shares = new Share[quorum];
                    int k = 0;

                    Iterator<BigInteger> it = shareholders.values().iterator();
                    while (k < quorum){
                        BigInteger shareholder = it.next();
                        if (corruptedShareholders.contains(shareholder)) {
                            continue;
                        }
                        VerifiableShare vs = extractShare(privateShares, shareholder);
                        shares[k++] = vs.getShare();
                    }

                    //corrupting share
                    if (corruptedShareholders.size() < faultyShares) {
                        shares[threshold + 1].setShare(BigInteger.ZERO);
                        corruptedShareholders.add(shares[threshold + 1].getShareholder());
                    }

                    OpenPublishedShares openShares = new OpenPublishedShares(shares, privateShares.getCommitments(), privateShares.getSharedData());
                    byte[] recoveredSecret = combine(openShares);
                    if (!Arrays.equals(recoveredSecret, secret))
                        throw new RuntimeException("Recovered Secret is different");
                }

            }
            double shareGeneration = mShareGeneration.getAverageInMillis(nDecimals);
            double commitmentsGeneration = mCommitmentsGeneration.getAverageInMillis(nDecimals);
            double sharesVerification = mShareValidation.getAverageInMillis(nDecimals);
            double secretReconstruction = mSharesCombine.getAverageInMillis(nDecimals);

            if (printResults) {
                System.out.println("Share generation[ms]: " + shareGeneration);
				System.out.println("Commitments generation[ms]: " + commitmentsGeneration);
				System.out.println("Share total[ms]: " + (shareGeneration + commitmentsGeneration));
				System.out.println();
				System.out.println("Shares verification[ms]: " + sharesVerification);
				System.out.println("Secret reconstruction[ms]: " + secretReconstruction);
				System.out.println("Combine total[ms]: " + (sharesVerification + secretReconstruction));
				if (faultyShares < maxFaultyShares) {
					System.out.println();
				}
			}
        }
    }

    private static OpenPublishedShares share(byte[] data) throws SecretSharingException {
        try {
            mShareGeneration.start();
            //Encrypting data
            BigInteger secretAsNumber = new BigInteger(field.bitLength() - 1, rndGenerator);
            byte[] secretKeyBytes = messageDigest.digest(secretAsNumber.toByteArray());

            SecretKey key = new SecretKeySpec(secretKeyBytes, dataEncryptionAlgorithm);
            byte[] sharedData = encrypt(dataCipher, data, key);

            //applying secret sharing scheme to encryption key
            Polynomial polynomial = new Polynomial(field, threshold, secretAsNumber, rndGenerator);
            mShareGeneration.stop();
            mCommitmentsGeneration.start();
            Commitment commitments = commitmentScheme.generateCommitments(polynomial);
            //Polynomial polynomial = createPolynomialOfSecret(secretAsNumber, coefficients);
            mCommitmentsGeneration.stop();
            mShareGeneration.start();
            //calculating shares
            Share[] shares = new Share[shareholders.size()];
            BigInteger shareholder;
            Iterator<BigInteger> it = shareholders.values().iterator();
            for (int i = 0; i < shareholders.size(); i++) {
                shareholder = it.next();
                shares[i] = new Share(shareholder, polynomial.evaluateAt(shareholder));
            }
            mShareGeneration.stop();
            return new OpenPublishedShares(shares, commitments, sharedData);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            throw new SecretSharingException("Error while creating shares.", e);
        }
    }

    private static VerifiableShare extractShare(OpenPublishedShares openShares, BigInteger shareholder) throws SecretSharingException {
        Share share = openShares.getShareOf(shareholder);
        if (share == null)
            throw new SecretSharingException("Share not found");
        return new VerifiableShare(share, openShares.getCommitments(), openShares.getSharedData());
    }

    private static byte[] combine(OpenPublishedShares openShares) throws SecretSharingException {
        BigInteger secretKeyAsNumber;
        mSharesCombine.start();
        Share[] shares = openShares.getShares();
        Share[] minimumShares = new Share[corruptedShareholders.size() < threshold ? threshold + 2 : threshold + 1];
        for (int i = 0, j = 0; i < shares.length && j < minimumShares.length; i++) {
            Share share = shares[i];
            if (!corruptedShareholders.contains(share.getShareholder()))
                minimumShares[j++] = share;
        }
        Polynomial polynomial = new Polynomial(field, minimumShares);
        mSharesCombine.stop();
        if (polynomial.getDegree() != threshold) {
            minimumShares = new Share[threshold + 1];
            int counter = 0;
            mShareValidation.start();
            for (Share share : shares) {
                if (corruptedShareholders.contains(share.getShareholder()))
                    continue;

                boolean valid = commitmentScheme.checkValidityWithoutPreComputation(share, openShares.getCommitments());

                if (counter <= threshold && valid)
                    minimumShares[counter++] = share;
                if (!valid)
                    corruptedShareholders.add(share.getShareholder());
            }
            mShareValidation.stop();

            if (counter <= threshold) {
                throw new SecretSharingException("Not enough valid shares!");
            }
            mSharesCombine.start();
            secretKeyAsNumber = interpolationStrategy.interpolateAt(BigInteger.ZERO, minimumShares);
        } else {
            mSharesCombine.start();
            secretKeyAsNumber = polynomial.getConstant();
        }

        byte[] keyBytes = messageDigest.digest(secretKeyAsNumber.toByteArray());
        SecretKey secretKey = new SecretKeySpec(keyBytes, dataEncryptionAlgorithm);
        try {
            byte[] b = decrypt(dataCipher, openShares.getSharedData(), secretKey);
            mSharesCombine.stop();
            return b;
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SecretSharingException("Error while decrypting secret!", e);
        }
    }

    private static byte[] encrypt(Cipher cipher, byte[] data, Key encryptionKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(Cipher cipher, byte[] data, Key decryptionKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
        return cipher.doFinal(data);
    }
}
