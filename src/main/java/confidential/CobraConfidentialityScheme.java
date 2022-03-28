package confidential;

import bftsmart.reconfiguration.views.View;
import confidential.polynomial.MissingProposalsMessage;
import confidential.polynomial.Proposal;
import confidential.polynomial.ProposalMessage;
import vss.Constants;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentUtils;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.commitment.ellipticCurve.EllipticCurveCommitmentScheme;
import vss.facade.SecretSharingException;
import vss.facade.VSSFacade;
import vss.interpolation.InterpolationStrategy;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author Robin
 */
public abstract class CobraConfidentialityScheme {
    protected final VSSFacade vss;
    private final Map<Integer, BigInteger> serverToShareholder;
    private final Map<BigInteger, Integer> shareholderToServer;
    private final Cipher cipher;
    private final Lock cipherLock;
    private final boolean isLinearCommitmentScheme;
    protected KeysManager keysManager;
    protected int threshold;
    private final EllipticCurveCommitmentScheme ellipticCurveCommitmentScheme;
    private final BigInteger ellipticCurveField;

    public CobraConfidentialityScheme(View view) throws SecretSharingException {
        cipherLock = new ReentrantLock(true);
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

        threshold = view.getF();
        Configuration configuration = Configuration.getInstance();

        Properties properties = new Properties();
        properties.put(Constants.TAG_THRESHOLD, String.valueOf(threshold));
        properties.put(Constants.TAG_DATA_ENCRYPTION_ALGORITHM, configuration.getDataEncryptionAlgorithm());
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
        isLinearCommitmentScheme = Configuration.getInstance().getVssScheme().equals("1");


        BigInteger prime = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        BigInteger order = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        BigInteger a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
        BigInteger b = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
        byte[] compressedGenerator = new BigInteger("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16).toByteArray();
        ellipticCurveField = order;
        ellipticCurveCommitmentScheme = new EllipticCurveCommitmentScheme(prime, order, a, b, compressedGenerator);
    }

    public BigInteger getField() {
        return vss.getField();
    }

    public InterpolationStrategy getInterpolationStrategy() {
        return vss.getInterpolationStrategy();
    }

    public boolean isLinearCommitmentScheme() {
        return isLinearCommitmentScheme;
    }

    public void addShareholder(int newServer, BigInteger shareholderId) throws SecretSharingException {
        vss.addShareholder(shareholderId);
        serverToShareholder.put(newServer, shareholderId);
        shareholderToServer.put(shareholderId, newServer);
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

    public byte[] encryptShareFor(int id, Share clearShare) throws SecretSharingException {
        Key encryptionKey = keysManager.getEncryptionKeyFor(id);

        try {
            return encrypt(clearShare.getShare().toByteArray(), encryptionKey);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new SecretSharingException("Failed to encrypt share", e);
        }
    }

    public BigInteger decryptShareFor(int id, byte[] encryptedShare) throws SecretSharingException {
        Key decryptionKey = keysManager.getDecryptionKeyFor(id);
        try {
            return new BigInteger(decrypt(encryptedShare, decryptionKey));
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

    protected byte[] encrypt(byte[] data, Key encryptionKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        try {
            cipherLock.lock();
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            return cipher.doFinal(data);
        } finally {
            cipherLock.unlock();
        }
    }

    protected byte[] decrypt(byte[] data, Key decryptionKey) throws InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        try {
            cipherLock.lock();
            cipher.init(Cipher.DECRYPT_MODE, decryptionKey);
            return cipher.doFinal(data);
        } finally {
            cipherLock.unlock();
        }
    }

    public BigInteger getEllipticCurveField() {
        return ellipticCurveField;
    }

    public Commitment generateEllipticCurveCommitment(Polynomial polynomial) {
        return ellipticCurveCommitmentScheme.generateCommitments(polynomial);
    }

    public boolean checkEllipticCurveCommitment(Share share, Commitment commitment) {
        return ellipticCurveCommitmentScheme.checkValidity(share, commitment);
    }

    public Commitment sumEllipticCurveCommitments(Commitment... commitments) throws SecretSharingException {
        return ellipticCurveCommitmentScheme.sumCommitments(commitments);
    }

    public void serializeProposalMessage(ProposalMessage message, ObjectOutput out) throws IOException {
        int id = message.getId();
        int sender = message.getSender();
        Proposal[] proposals = message.getProposals();
        byte[] signature = message.getSignature();

        out.writeInt(id);
        out.writeInt(sender);
        out.writeInt(proposals == null ? -1 : proposals.length);
        if (proposals != null) {
            for (Proposal proposal : proposals) {
                writeProposal(proposal, out);
            }
        }
        out.writeInt(signature == null ? -1 : signature.length);
        if (signature != null)
            out.write(signature);
    }

    public void serializeMissingProposalMessage(MissingProposalsMessage message, ObjectOutput out) throws IOException {
        int id = message.getId();
        int sender = message.getSender();
        ProposalMessage proposal = message.getMissingProposal();
        out.writeInt(id);
        out.writeInt(sender);
        serializeProposalMessage(proposal, out);
    }

    public ProposalMessage deserializeProposalMessage(ObjectInput in) throws IOException, ClassNotFoundException {
        int id = in.readInt();
        int sender = in.readInt();
        Proposal[] proposals = null;
        byte[] signature = null;

        int len = in.readInt();
        if (len != -1) {
            proposals = new Proposal[len];
            for (int i = 0; i < len; i++) {
                proposals[i] = readProposal(in);
            }
        }
        len = in.readInt();
        if (len != -1) {
            signature = new byte[len];
            in.readFully(signature);
        }
        ProposalMessage proposalMessage = new ProposalMessage(id, sender, proposals);
        proposalMessage.setSignature(signature);
        return proposalMessage;
    }

    public MissingProposalsMessage deserializeMissingProposalMessage(ObjectInput in) throws IOException, ClassNotFoundException {
        int id = in.readInt();
        int sender = in.readInt();
        ProposalMessage proposal = deserializeProposalMessage(in);
        return new MissingProposalsMessage(id, sender, proposal);
    }

    private void writeProposal(Proposal proposal, ObjectOutput out) throws IOException {
        Map<Integer, byte[]> points = proposal.getPoints();
        Commitment commitments = proposal.getCommitments();
        out.writeInt(points == null ? -1 : points.size());
        if (points != null) {
            for (Map.Entry<Integer, byte[]> entry : points.entrySet()) {
                out.writeInt(entry.getKey());
                byte[] b = entry.getValue();
                out.writeInt(b.length);
                out.write(b);

            }
        }
        out.writeBoolean(commitments != null);
        if (commitments != null) {
            out.writeBoolean(commitments instanceof EllipticCurveCommitment);
            if (commitments instanceof EllipticCurveCommitment)
                ellipticCurveCommitmentScheme.writeCommitment(commitments, out);
            else
                CommitmentUtils.getInstance().writeCommitment(commitments, out);
        }
    }

    private Proposal readProposal(ObjectInput in) throws IOException, ClassNotFoundException {
        Map<Integer, byte[]> points = null;
        int size = in.readInt();
        if (size != -1) {
            points = new HashMap<>(size);
            byte[] b;
            while (size-- > 0) {
                int shareholder = in.readInt();
                b = new byte[in.readInt()];
                in.readFully(b);
                points.put(shareholder, b);
            }
        }
        Commitment commitment = null;
        if (in.readBoolean()) {
            if (in.readBoolean()) {
                commitment = ellipticCurveCommitmentScheme.readCommitment(in);
            } else {
                commitment = CommitmentUtils.getInstance().readCommitment(in);
            }
        }
        return new Proposal(points, commitment);
    }
}
