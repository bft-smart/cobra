package vss.secretsharing;

import vss.Constants;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentUtils;
import vss.commitment.constant.KateCommitmentScheme;
import vss.commitment.linear.FeldmanCommitmentScheme;
import vss.facade.Mode;
import vss.facade.SecretSharingException;
import vss.interpolation.InterpolationStrategy;
import vss.interpolation.LagrangeInterpolation;
import vss.polynomial.Polynomial;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Implements Shamir's Secret Sharing scheme.
 * Confidential data is encrypted using random encryption key and shares are of encryption key.
 *
 * @author Robin
 */
public class VerifiableSecretSharing {
    private final String dataEncryptionAlgorithm;
    private final BigInteger field;
    private final SecureRandom rndGenerator;
    private final Cipher dataCipher;
    protected Map<Integer, BigInteger> shareholders;
    protected final CommitmentScheme commitmentScheme;
    private final InterpolationStrategy interpolationStrategy;
    private final Set<BigInteger> corruptedShareholders;
    private int threshold;
    private final MessageDigest messageDigest;
    private final Lock dataEncryptionLock;

    public VerifiableSecretSharing(Properties properties, BigInteger[] shareholders) throws SecretSharingException {
        if (properties == null || shareholders == null)
            throw new IllegalArgumentException("Properties or shareholders cannot be null!");
        this.threshold = Integer.parseInt(properties.getProperty(Constants.TAG_THRESHOLD));
        this.dataEncryptionAlgorithm = properties.getProperty(Constants.TAG_DATA_ENCRYPTION_ALGORITHM);

        String commitmentSchemeName = properties.getProperty(Constants.TAG_COMMITMENT_SCHEME);
        if (commitmentSchemeName.equals(Constants.VALUE_FELDMAN_SCHEME)) {
            BigInteger p = new BigInteger(properties.getProperty(Constants.TAG_PRIME_FIELD), 16);
            BigInteger generator = new BigInteger(properties.getProperty(Constants.TAG_GENERATOR), 16);
            this.commitmentScheme = new FeldmanCommitmentScheme(p, generator);
            this.field = new BigInteger(properties.getProperty(Constants.TAG_SUB_FIELD), 16);
        } else if (commitmentSchemeName.equals(Constants.VALUE_KATE_SCHEME)) {
            KateCommitmentScheme kateCommitmentScheme = new KateCommitmentScheme(threshold, shareholders);
            this.field = kateCommitmentScheme.getPrimeFieldOrder();
            this.commitmentScheme = kateCommitmentScheme;
        } else
            throw new SecretSharingException("Unknown commitment scheme: " + commitmentSchemeName);

        this.rndGenerator = new SecureRandom();
        this.interpolationStrategy = new LagrangeInterpolation(field);

        this.corruptedShareholders = new HashSet<>();

        try {
            dataCipher = Cipher.getInstance(dataEncryptionAlgorithm);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new SecretSharingException("Cipher initialization error.", e);
        }

        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new SecretSharingException("Failed to initialize Message Digest", e);
        }

        this.shareholders = new HashMap<>(shareholders.length);
        for (BigInteger shareholder : shareholders) {
            if (shareholder.equals(BigInteger.ZERO))
                throw new SecretSharingException("Shareholder can't have id = 0");
            else
                this.shareholders.put(shareholder.hashCode(), shareholder);
        }
        dataEncryptionLock = new ReentrantLock(true);
        CommitmentUtils.initialize(commitmentScheme);
    }

    /**
     * Returns commitment scheme used to allows verification of shares
     * @return Commitment scheme
     */
    public CommitmentScheme getCommitmentScheme() {
        return commitmentScheme;
    }

    /**
     * Returns polynomial interpolation strategy used to interpolate polynomials given shares
     * @return Interpolation strategy
     */
    public InterpolationStrategy getInterpolationStrategy() {
        return interpolationStrategy;
    }

    /**
     * Adds the new shareholder to the current set of shareholders
     * @param shareholder Shareholder id
     * @throws SecretSharingException When shareholder id is not greater than zero
     */
    public void addShareholder(BigInteger shareholder) throws SecretSharingException {
        if (shareholder.equals(BigInteger.ZERO))
            throw new SecretSharingException("Shareholder can't have id = 0");
        shareholders.put(shareholder.hashCode(), shareholder);
        commitmentScheme.addShareholder(shareholder);
        interpolationStrategy.addShareholder(shareholder);
    }

    /**
     * Removes the shareholder if it exists in the current set of shareholders
     * @param shareholder Shareholder
     */
    public void removeShareholder(BigInteger shareholder) {
        shareholders.remove(shareholder.hashCode());
        commitmentScheme.removeShareholder(shareholder);
        interpolationStrategy.removeShareholder(shareholder);
    }

    public void updateThreshold(int newThreshold) {
        this.threshold = newThreshold;
    }

    public BigInteger getField() {
        return field;
    }

    /**
     * Computes shares for a given threshold
     * @param data Secret data
     * @param mode See {@link Mode}
     * @param threshold Fault tolerance
     * @return Shares of the secret data with the corresponding commitments
     * @throws SecretSharingException This exception is thrown in three possible cases:
     *  (1) If mode == LARGE_SECRET, it was not possible to encrypt the secret data;
     *  (2) If mode == SMALL_SECRET, the encoded data is out of the interval [0, field[
     *  (3) The requested mode is unsupported.
     */
    public OpenPublishedShares share(byte[] data, Mode mode, int threshold) throws SecretSharingException {
        try {
            BigInteger secretAsNumber;
            byte[] sharedData = null;
            switch (mode) {
                case LARGE_SECRET:
                    //generating a random encryption key
                    secretAsNumber = new BigInteger(field.bitLength() - 1, rndGenerator);
                    //Encrypting data
                    byte[] secretKeyBytes = messageDigest.digest(secretAsNumber.toByteArray());

                    SecretKey key = new SecretKeySpec(secretKeyBytes, dataEncryptionAlgorithm);
                    sharedData = encrypt(dataCipher, data, key, dataEncryptionLock);
                    break;
                case SMALL_SECRET:
                    secretAsNumber = new BigInteger(data);
                    if (secretAsNumber.compareTo(BigInteger.ZERO) < 0 || secretAsNumber.compareTo(field) >= 0)
                        throw new SecretSharingException("Encoded secret data is out of the interval [0, field[");
                    break;
                default:
                    throw new SecretSharingException("Unsupported mode " + mode);
            }

            Polynomial polynomial = new Polynomial(field, threshold, secretAsNumber, rndGenerator);
            Commitment commitments = commitmentScheme.generateCommitments(polynomial);

            //calculating shares
            Share[] shares = new Share[shareholders.size()];
            BigInteger shareholder;
            Iterator<BigInteger> it = shareholders.values().iterator();
            for (int i = 0; i < shareholders.size(); i++) {
                shareholder = it.next();
                shares[i] = new Share(shareholder, polynomial.evaluateAt(shareholder));
            }

            return new OpenPublishedShares(shares, commitments, sharedData);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            throw new SecretSharingException("Error while creating shares.", e);
        }
    }

    public void clearCorruptedShareholderList() {
        corruptedShareholders.clear();
    }

    /**
     * Combines shares to reconstruct the confidential data
     * @param openShares Shares and corresponding commitments
     * @param mode See {@link Mode}
     * @param threshold Fault tolerance
     * @return Reconstructed confidential data
     * @throws SecretSharingException If failed to reconstruct the data or the requested mode is unsupported.
     */
    public byte[] combine(OpenPublishedShares openShares, Mode mode, int threshold) throws SecretSharingException {
        Commitment commitments = openShares.getCommitments();
        BigInteger secretKeyAsNumber;
        Share[] shares = openShares.getShares();
        Share[] minimumShares = new Share[corruptedShareholders.size() < threshold ? threshold + 2 : threshold + 1];
        for (int i = 0, j = 0; i < shares.length && j < minimumShares.length; i++) {
            Share share = shares[i];
            if (!corruptedShareholders.contains(share.getShareholder()))
                minimumShares[j++] = share;
        }
        Polynomial polynomial = new Polynomial(field, minimumShares);
        if (polynomial.getDegree() != threshold) {
            minimumShares = new Share[threshold + 1];
            int counter = 0;

            commitmentScheme.startVerification(openShares.getCommitments());
            for (Share share : shares) {
                if (corruptedShareholders.contains(share.getShareholder()))
                    continue;
                boolean valid = commitmentScheme.checkValidity(share, commitments);

                if (counter <= threshold && valid)
                    minimumShares[counter++] = share;
                if (!valid)
                    corruptedShareholders.add(share.getShareholder());
            }
            commitmentScheme.endVerification();
            if (counter <= threshold)
                throw new SecretSharingException("Not enough valid shares!");
            secretKeyAsNumber = interpolationStrategy.interpolateAt(BigInteger.ZERO, minimumShares);
        } else {
            secretKeyAsNumber = polynomial.getConstant();
        }

        switch (mode) {
            case LARGE_SECRET:
                byte[] keyBytes = messageDigest.digest(secretKeyAsNumber.toByteArray());
                SecretKey secretKey = new SecretKeySpec(keyBytes, dataEncryptionAlgorithm);
                try {
                    return decrypt(dataCipher, openShares.getSharedData(), secretKey, dataEncryptionLock);
                } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                    throw new SecretSharingException("Error while decrypting secret!", e);
                }
            case SMALL_SECRET:
                return secretKeyAsNumber.toByteArray();
            default:
                throw new SecretSharingException("Unsupported mode " + mode);
        }

    }

    /**
     * Encrypts given data using cipher with encryptionKey of corresponding algorithm used to instantiate cipher
     * @param cipher Cipher used to encrypt data
     * @param data Data to encrypt
     * @param encryptionKey Encryption key
     * @return Encrypted data
     * @throws InvalidKeyException When encryptionKey is invalid
     * @throws BadPaddingException When fails to encrypt
     * @throws IllegalBlockSizeException When fails to encrypt
     */
    protected static byte[] encrypt(Cipher cipher, byte[] data, Key encryptionKey, Lock encryptionLock) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        encryptionLock.lock();
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        byte[] result = cipher.doFinal(data);
        encryptionLock.unlock();
        return result;
    }

    /**
     * Decrypts a data using cipher if corresponding decryption key is valid
     * @param cipher Cipher used to decrypt data
     * @param data Encrypted data
     * @param decryptionKey Decryption key
     * @return Decrypted data
     * @throws InvalidKeyException When decryptionKey is invalid
     * @throws BadPaddingException When fails to encrypt
     * @throws IllegalBlockSizeException When fails to encrypt
     */
    protected static byte[] decrypt(Cipher cipher, byte[] data, Key decryptionKey, Lock encryptionLock) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        encryptionLock.lock();
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
        byte[] result = cipher.doFinal(data);
        encryptionLock.unlock();
        return result;
    }
}
