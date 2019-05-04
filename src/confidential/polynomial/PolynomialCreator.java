package confidential.polynomial;

import bftsmart.tom.util.TOMUtil;
import confidential.interServersCommunication.InterServersCommunication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.CommitmentScheme;
import vss.commitment.Commitments;
import vss.polynomial.Polynomial;
import vss.polynomial.Term;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.*;

import static confidential.Configuration.defaultKeys;
import static confidential.Configuration.shareEncryptionAlgorithm;

public class PolynomialCreator {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private int id;
    private int bitLength;
    private BigInteger field;
    private SecureRandom rndGenerator;
    private Cipher cipher;
    private CommitmentScheme commitmentScheme;
    private InterServersCommunication serversCommunication;
    private int f;
    private int processId;
    private BigInteger shareholderId;
    private NewPolynomialMessage newPolynomialMessage;
    private Map<Integer, ProposalMessage> proposals;
    private Map<Integer, ProposalMessage> finalProposalSet;
    private Map<Integer, BigInteger> decryptedPoints;
    private List<byte[]> missingProposals;
    private boolean acceptNewProposals;
    private Share polynomialPropertyShare;
    private int d;
    private Set<Integer> conflictList;
    private Set<Integer> acceptList;
    private List<VoteMessage> votes;
    private PolynomialCreationListener creationListener;
    private List<byte[]> invalidProposals;
    private SecretKey defaultKey = new SecretKeySpec(defaultKeys[0].toByteArray(), "AES");


    public PolynomialCreator(int id, int processId, BigInteger shareholderId, BigInteger field, int f, SecureRandom rndGenerator,
                             Cipher cipher, CommitmentScheme commitmentScheme,
                             InterServersCommunication serversCommunication, PolynomialCreationListener creationListener) {
        this.id = id;
        this.processId = processId;
        this.field = field;
        this.f = f;
        this.bitLength = field.bitLength() - 1;
        this.rndGenerator = rndGenerator;
        this.cipher = cipher;
        this.commitmentScheme = commitmentScheme;
        this.serversCommunication = serversCommunication;
        this.acceptNewProposals = true;
        this.proposals = new HashMap<>();
        this.finalProposalSet = new HashMap<>();
        this.decryptedPoints = new HashMap<>();
        this.shareholderId = shareholderId;
        this.conflictList = new HashSet<>();
        this.acceptList = new HashSet<>();
        this.votes = new LinkedList<>();
        this.creationListener = creationListener;
    }

    public int getId() {
        return id;
    }

    public PolynomialMessage generateProposal(NewPolynomialMessage newPolynomialMessage) {
        this.newPolynomialMessage = newPolynomialMessage;
        this.polynomialPropertyShare = new Share(newPolynomialMessage.getX(), newPolynomialMessage.getY());
        //generating f coefficients
        BigInteger[] coefficients = generateRandomNumbers(f);

        //generating polynomial of degree f
        Polynomial polynomial = new Polynomial(field);
        for (int i = 0; i < coefficients.length; i++) {
            BigInteger coefficient = coefficients[i];
            BigInteger exponent = BigInteger.valueOf(i + 1);
            polynomial.addTerm(new Term() {
                @Override
                public BigInteger evaluateAt(BigInteger x) {
                    return coefficient.multiply(x.modPow(exponent, field));
                }
            });
        }

        BigInteger independentTerm = newPolynomialMessage.getY().subtract(
                polynomial.evaluateAt(newPolynomialMessage.getX()));
        polynomial.addTerm(new Term() {
            @Override
            public BigInteger evaluateAt(BigInteger bigInteger) {
                return independentTerm;
            }
        });

        //Committing to polynomial
        Commitments commitments = commitmentScheme.generateCommitments(independentTerm, coefficients);

        //generating encrypted points for each member
        int[] members = newPolynomialMessage.getViewMembers();
        byte[][] encryptedPoints = new byte[members.length][];
        for (int i = 0; i < members.length; i++) {
            BigInteger point = polynomial.evaluateAt(BigInteger.valueOf(members[i] + 1));
            encryptedPoints[i] = encrypt(serversCommunication.getSecretKey(members[i]), point);
        }

        return new ProposalMessage(
                id,
                processId,
                newPolynomialMessage.getViewId(),
                newPolynomialMessage.getLeader(),
                newPolynomialMessage.getViewMembers(),
                encryptedPoints,
                commitments);
    }

    public void processProposal(byte[] serializedMessage, ProposalMessage message) {
        if (!acceptNewProposals) {
            logger.debug("I already have {} proposals (2f + 1)", proposals.size());
            return;
        }

        byte[] cryptHash = TOMUtil.computeHash(serializedMessage);
        message.setCryptographicHash(cryptHash);
        proposals.put(Arrays.hashCode(cryptHash), message);
        if (proposals.size() > 2 * f)
            acceptNewProposals = false;
    }

    public PolynomialMessage generateProposalSet() {
        if (proposals.size() <= 2 * f)
            return null;
        int[] receivedNodes = new int[proposals.size()];
        byte[][] receivedProposalsHashes = new byte[proposals.size()][];
        int i = 0;
        for (Map.Entry<Integer, ProposalMessage> e : proposals.entrySet()) {
            receivedNodes[i] = e.getValue().getSender();
            receivedProposalsHashes[i] = e.getValue().getCryptographicHash();
            i++;
            finalProposalSet.put(e.getKey(), e.getValue());
        }

        return new ProposalSetMessage(
                id,
                processId,
                newPolynomialMessage.getViewId(),
                newPolynomialMessage.getLeader(),
                newPolynomialMessage.getViewMembers(),
                receivedNodes,
                receivedProposalsHashes
        );
    }

    public PolynomialMessage processProposalSet(ProposalSetMessage message) {
        invalidProposals = new LinkedList<>();
        int[] receivedNodes = message.getReceivedNodes();
        byte[][] receivedProposals = message.getReceivedProposals();
        int myIndex = getIndexOf(processId, message.getViewMembers());
        SecretKey myKey = serversCommunication.getSecretKey(processId);

        for (int i = 0; i < receivedNodes.length; i++) {
            int proposalHash = Arrays.hashCode(receivedProposals[i]);
            ProposalMessage proposal = proposals.get(proposalHash);
            if (proposal == null) {
                logger.debug("I don't have proposal of {} with id {}", receivedNodes[i], id);
                if (missingProposals == null)
                    missingProposals = new LinkedList<>();
                missingProposals.add(receivedProposals[i]);
                continue;
            }

            byte[] encryptedPoint = proposal.getEncryptedPoints()[myIndex];
            BigInteger point = decrypt(myKey, encryptedPoint);
            finalProposalSet.put(proposalHash, proposal);
            decryptedPoints.put(proposalHash, point);
            if (!isValidPoint(point, proposal.getCommitments()))
                invalidProposals.add(proposal.getCryptographicHash());
        }

        if (missingProposals != null)
            return null;
        byte[][] invalidProposalArray = new byte[invalidProposals.size()][];
        int counter = 0;
        for (byte[] invalidProposal : invalidProposals)
            invalidProposalArray[counter++] = invalidProposal;
        return new VoteMessage(
                id,
                processId,
                newPolynomialMessage.getViewId(),
                newPolynomialMessage.getLeader(),
                newPolynomialMessage.getViewMembers(),
                invalidProposalArray
        );
    }

    public PolynomialMessage requestMissingProposals() {
        byte[][] missingProposalsArray = new byte[missingProposals.size()][];
        int i = 0;
        for (byte[] missingProposal : missingProposals) {
            missingProposalsArray[i++] = missingProposal;
        }

        return new MissingProposalRequestMessage(
                id,
                processId,
                newPolynomialMessage.getViewId(),
                newPolynomialMessage.getLeader(),
                newPolynomialMessage.getViewMembers(),
                missingProposalsArray
        );
    }

    public PolynomialMessage processMissingProposals(MissingProposalsMessage message) {
        ProposalMessage[] missingProposals = message.getMissingProposals();
        int myIndex = getIndexOf(processId, message.getViewMembers());
        SecretKey myKey = serversCommunication.getSecretKey(processId);

        for (ProposalMessage proposal : missingProposals) {
            byte[] serializedProposal = serialize(proposal);
            proposal.setCryptographicHash(TOMUtil.computeHash(serializedProposal));
            int proposalHash = Arrays.hashCode(proposal.getCryptographicHash());

            byte[] encryptedPoint = proposal.getEncryptedPoints()[myIndex];
            BigInteger point = decrypt(myKey, encryptedPoint);
            finalProposalSet.put(proposalHash, proposal);
            decryptedPoints.put(proposalHash, point);
            if (!isValidPoint(point, proposal.getCommitments()))
                invalidProposals.add(proposal.getCryptographicHash());
        }
        byte[][] invalidProposalArray = new byte[invalidProposals.size()][];
        int counter = 0;
        for (byte[] invalidProposal : invalidProposals)
            invalidProposalArray[counter++] = invalidProposal;
        return new VoteMessage(
                id,
                processId,
                newPolynomialMessage.getViewId(),
                newPolynomialMessage.getLeader(),
                newPolynomialMessage.getViewMembers(),
                invalidProposalArray
        );
    }

    public boolean processVote(VoteMessage message) {
        if (acceptList.size() >= 2 * f + 1 - d)
            return true;
        votes.add(message);
        if (conflictList.contains(message.getSender()))
            return false;
        boolean hasAccusation = false;
        for (byte[] accusation : message.getInvalidProposals()) {
            int proposalHash = Arrays.hashCode(accusation);
            ProposalMessage proposal = finalProposalSet.get(proposalHash);
            if (proposal != null) {
                hasAccusation = true;
                finalProposalSet.remove(proposalHash);
                decryptedPoints.remove(proposalHash);
                Map.Entry<Integer, ProposalMessage> senderProposal = null;
                for (Map.Entry<Integer, ProposalMessage> e : finalProposalSet.entrySet()) {
                    if (e.getValue().getSender() == message.getSender()) {
                        senderProposal = e;
                        break;
                    }
                }

                if (senderProposal != null) {
                    finalProposalSet.remove(senderProposal.getKey());
                    decryptedPoints.remove(senderProposal.getKey());
                }
                d++;
                conflictList.add(proposal.getSender());
                conflictList.add(message.getSender());
                acceptList.remove(proposal.getSender());
                acceptList.remove(message.getSender());
                break;
            }
        }
        if (!hasAccusation)
            acceptList.add(message.getSender());

        return acceptList.size() >= 2 * f + 1 - d;
    }

    public PolynomialMessage getProcessedVotes() {
        return new ProcessedVotesMessage(
                id,
                processId,
                newPolynomialMessage.getViewId(),
                newPolynomialMessage.getLeader(),
                newPolynomialMessage.getViewMembers(),
                votes
        );
    }

    public boolean processVotes(ProcessedVotesMessage message) {
        if (!acceptList.isEmpty())
            return true;
        boolean terminated = false;
        for (VoteMessage vote : message.getVotes()) {
            terminated = processVote(vote);
        }
        return terminated;
    }


    public PolynomialMessage generateMissingProposalsResponse(MissingProposalRequestMessage message) {
        ProposalMessage[] missingProposals = new ProposalMessage[message.getMissingProposals().length];
        for (int i = 0; i < missingProposals.length; i++) {
            int hash = Arrays.hashCode(message.getMissingProposals()[i]);
            missingProposals[i] = proposals.get(hash);
        }

        return new MissingProposalsMessage(
                id,
                processId,
                newPolynomialMessage.getViewId(),
                newPolynomialMessage.getLeader(),
                newPolynomialMessage.getViewMembers(),
                missingProposals
        );
    }

    public void deliverResult() {
        logger.debug("I have selected {} proposals", finalProposalSet.size());
        finalProposalSet.values().forEach(p -> logger.debug("Proposal from {}", p.getSender()));

        BigInteger finalPoint = BigInteger.ONE;
        Commitments[] allCommitments = new Commitments[finalProposalSet.size()];
        int i = 0;
        for (Map.Entry<Integer, BigInteger> e : decryptedPoints.entrySet()) {
            finalPoint = finalPoint.add(e.getValue());
            allCommitments[i++] = finalProposalSet.get(e.getKey()).getCommitments();
        }
        Share share = new Share(shareholderId, finalPoint);
        Commitments commitments = commitmentScheme.sumCommitments(allCommitments);
        VerifiableShare point =  new VerifiableShare(share, commitments, null);

        creationListener.onPolynomialCreation(newPolynomialMessage.getReason(), newPolynomialMessage.getId(), point);
    }

    private boolean isValidPoint(BigInteger point, Commitments commitments) {
        Share share = new Share(shareholderId, point);
        if (!commitmentScheme.checkValidity(share, commitments)) //point is on the polynomial?
            return false;
        if (!commitmentScheme.checkValidity(polynomialPropertyShare, commitments)) //the polynomial has the required property
            return false;
        return true;
    }

    private static int getIndexOf(int id, int[] members) {
        for (int i = 0; i < members.length; i++)
            if (members[i] == id)
                return i;
        return -1;
    }

    private byte[] encrypt(Key key, BigInteger data) {
        key = defaultKey;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data.toByteArray());
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            logger.error("Failed to encrypt data", e);
        }
        return null;
    }

    private BigInteger decrypt(Key key, byte[] encryptedData) {
        key = defaultKey;
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new BigInteger(cipher.doFinal(encryptedData));
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            logger.error("Failed to decipher data", e);
        }
        return null;
    }

    private byte[] serialize(PolynomialMessage message) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            message.writeExternal(out);
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.warn("Polynomial message serialization failed", e);
        }
        return null;
    }

    /**
     * Generate random number n. n > 0 && n <= 2^bitLength
     * @return Random number
     */
    private BigInteger randomNumber() {
        BigInteger rndBig = new BigInteger(bitLength, rndGenerator);
        if (rndBig.compareTo(BigInteger.ZERO) == 0)
            rndBig = rndBig.add(BigInteger.ONE);
        return rndBig;
    }

    private BigInteger[] generateRandomNumbers(int threshold) {
        BigInteger[] numbers = new BigInteger[threshold];

        for (int i = 0; i < numbers.length; i++)
            numbers[i] = randomNumber();
        return numbers;
    }
}
