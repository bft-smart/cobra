package confidential;

import bftsmart.reconfiguration.views.View;
import vss.Constants;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.secretsharing.EncryptedShare;
import vss.secretsharing.Share;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static confidential.Configuration.*;

/**
 * @author Robin
 */
public abstract class CobraConfidentialityScheme {
    protected final VSSFacade vss;
    private final Map<Integer, BigInteger> serverToShareholder;
    private final Map<BigInteger, Integer> shareholderToServer;
    private Cipher cipher;
    protected KeysManager keysManager;

    public CobraConfidentialityScheme(View view) throws SecretSharingException {
        int[] processes = view.getProcesses();
        serverToShareholder = new HashMap<>(processes.length);
        shareholderToServer = new HashMap<>(processes.length);
        BigInteger[] shareholders = new BigInteger[processes.length];
        for (int i = 0; i < processes.length; i++) {
            int process = processes[i];
            BigInteger shareholder = BigInteger.valueOf(process + 1);
            serverToShareholder.put(process, shareholder);
            shareholderToServer.put(shareholder, process);
            shareholders[i] = shareholder;
        }

        int threshold = view.getF();
        Configuration configuration = Configuration.getInstance();

        Properties properties = new Properties();
        properties.put(Constants.TAG_THRESHOLD, String.valueOf(threshold));
        properties.put(Constants.TAG_DATA_ENCRYPTION_ALGORITHM, configuration.getDataEncryptionAlgorithm());
        properties.put(Constants.TAG_SHARE_ENCRYPTION_ALGORITHM, configuration.getShareEncryptionAlgorithm());
        properties.put(Constants.TAG_COMMITMENT_SCHEME, configuration.getVssScheme());
        if (configuration.getVssScheme().equals("1")) {
            properties.put(Constants.TAG_PRIME_FIELD, configuration.getPrimeField());
            properties.put(Constants.TAG_SUB_FIELD, configuration.getSubPrimeField());
            properties.put(Constants.TAG_GENERATOR, configuration.getGenerator());
        }
        try {
            cipher = Cipher.getInstance(configuration.getShareEncryptionAlgorithm());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SecretSharingException("Failed to initialize the cipher");
        }
        vss = new VSSFacade(properties, shareholders);
        keysManager = new KeysManager();
    }

    public CommitmentScheme getCommitmentScheme() {
        return vss.getCommitmentScheme();
    }

    public BigInteger getShareholder(int process) {
        return serverToShareholder.get(process);
    }

    public int getProcess(BigInteger shareholder) {
        return shareholderToServer.get(shareholder);
    }

    public void updateParameters(View view) {
        throw new UnsupportedOperationException("Not implemented");
    }

    public EncryptedShare encryptShareFor(int id, Share clearShare) throws SecretSharingException {
        Key encryptionKey = keysManager.getEncryptionKeyFor(id);

        try {
            return new EncryptedShare(clearShare.getShareholder(),
                    encrypt(clearShare.getShare().toByteArray(), encryptionKey));
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SecretSharingException("Failed to encrypt share", e);
        }
    }

    public PublicKey getSigningPublicKeyFor(int id) {
        return keysManager.getSigningPublicKeyFor(id);
    }

    public PrivateKey getSigningPrivateKey() {
        return keysManager.getSigningKey();
    }

    public byte[] encryptDataFor(int id, byte[] data) {
        Key encryptionKey = keysManager.getEncryptionKeyFor(id);

        try {
            return encrypt(data, encryptionKey);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            return null;
        }
    }

    public Share decryptShare(int id, EncryptedShare encryptedShare) throws SecretSharingException {
        Key decryptionKey = keysManager.getDecryptionKeyFor(id);
        try {
            return new Share(encryptedShare.getShareholder(),
                    new BigInteger(decrypt(encryptedShare.getEncryptedShare(), decryptionKey)));
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SecretSharingException("Failed to decrypt share", e);
        }
    }

    public byte[] decryptData(int id, byte[] encryptedData) {
        Key decryptionKey = keysManager.getDecryptionKeyFor(id);
        try {
            return decrypt(encryptedData, decryptionKey);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            return null;
        }
    }

    private byte[] encrypt(byte[] data, Key encryptionKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        return cipher.doFinal(data);
    }

    private byte[] decrypt(byte[] data, Key decryptionKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
        return cipher.doFinal(data);
    }
}
