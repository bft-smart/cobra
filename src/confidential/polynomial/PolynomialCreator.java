package confidential.polynomial;

import bftsmart.tom.util.TOMUtil;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.interServersCommunication.InterServersMessageType;
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

class PolynomialCreator {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private PolynomialContext context;
    private final int myIndex;
    private final int bitLength;
    private final BigInteger field;
    private final SecureRandom rndGenerator;
    private final Cipher cipher;
    private final CommitmentScheme commitmentScheme;
    private final InterServersCommunication serversCommunication;
    private final int processId;
    private final BigInteger shareholderId;
    private final Map<Integer, ProposalMessage> proposals;
    private final Map<Integer, ProposalMessage> finalProposalSet;
    private final Map<Integer, BigInteger> decryptedPoints;
    private List<byte[]> missingProposals;
    private final Share polynomialPropertyShare;
    private int d;
    private final Set<Integer> conflictList;
    private final Set<Integer> acceptList;
    private final List<VoteMessage> votes;
    private final PolynomialCreationListener creationListener;
    private List<byte[]> invalidProposals;
    private SecretKey defaultKey = new SecretKeySpec(defaultKeys[0].toByteArray(), "AES");
    private final Set<Integer> newPolynomialRequestsFrom;
    private ProcessedVotesMessage processedVotesMessage;

    PolynomialCreator(PolynomialContext context,
                      int processId,
                      BigInteger shareholderId,
                      BigInteger field,
                      SecureRandom rndGenerator,
                      Cipher cipher,
                      CommitmentScheme commitmentScheme,
                      InterServersCommunication serversCommunication,
                      PolynomialCreationListener creationListener) {
        this.context = context;
        this.processId = processId;
        this.shareholderId = shareholderId;
        this.field = field;
        this.bitLength = field.bitLength() - 1;
        this.polynomialPropertyShare = new Share(context.getX(), context.getY());
        this.rndGenerator = rndGenerator;
        this.cipher = cipher;
        this.commitmentScheme = commitmentScheme;
        this.serversCommunication = serversCommunication;
        this.creationListener = creationListener;

        int maxMessages = context.getMembers().length;

        this.proposals = new HashMap<>(maxMessages);
        this.finalProposalSet = new HashMap<>(maxMessages);
        this.decryptedPoints = new HashMap<>(maxMessages);
        this.conflictList = new HashSet<>(maxMessages);
        this.acceptList = new HashSet<>(maxMessages);
        this.votes = new ArrayList<>(maxMessages);
        this.newPolynomialRequestsFrom = new HashSet<>(maxMessages);
        this.myIndex = getIndexOf(processId, context.getMembers());
    }

    void sendNewPolynomialCreationRequest() {
        NewPolynomialMessage newPolynomialMessage = new NewPolynomialMessage(
                processId, context);
        logger.debug("Sending NewPolynomialMessage to {} with id {}", Arrays.toString(context.getMembers()),
                context.getId());
        serversCommunication.sendUnordered(InterServersMessageType.NEW_POLYNOMIAL, serialize(newPolynomialMessage),
                context.getMembers());
    }

    void processNewPolynomialMessage(NewPolynomialMessage newPolynomialMessage) {
        if (newPolynomialRequestsFrom.size() > 2 * context.getF() + 1) {
            logger.debug("I already have 2f+1 new polynomial Messages");
            return;
        }

        if (newPolynomialRequestsFrom.contains(newPolynomialMessage.getSender())) {
            logger.debug("Duplicated new polynomial request from {} with id {}",
                    newPolynomialMessage.getSender(), newPolynomialMessage.getId());
            return;
        }

        if (!context.equals(newPolynomialMessage.getContext())) {
            logger.debug("New polynomial message from {} with id {} has different context",
                    newPolynomialMessage.getSender(),
                    newPolynomialMessage.getId());
            return;
        }

        newPolynomialRequestsFrom.add(newPolynomialMessage.getSender());

        logger.debug("I have {} requests to start creation of new polynomial with id {}",
                newPolynomialRequestsFrom.size(), context.getId());

        if (newPolynomialRequestsFrom.size() > 2 * context.getF())
            generateAndSendProposal();
    }

    private void generateAndSendProposal() {
        //generating f coefficients
        BigInteger[] coefficients = generateRandomNumbers(context.getF());

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

        BigInteger independentTerm = polynomialPropertyShare.getShare().subtract(
                polynomial.evaluateAt(polynomialPropertyShare.getShareholder()));
        polynomial.addTerm(new Term() {
            @Override
            public BigInteger evaluateAt(BigInteger bigInteger) {
                return independentTerm;
            }
        });

        //Committing to polynomial
        Commitments commitments = commitmentScheme.generateCommitments(independentTerm, coefficients);

        //generating encrypted points for each member
        byte[][] encryptedPoints = new byte[context.getMembers().length][];
        for (int i = 0; i < context.getMembers().length; i++) {
            BigInteger point = polynomial.evaluateAt(BigInteger.valueOf(context.getMembers()[i] + 1));
            encryptedPoints[i] = encrypt(serversCommunication.getSecretKey(context.getMembers()[i]), point);
        }

        ProposalMessage proposalMessage = new ProposalMessage(
                context.getId(),
                processId,
                encryptedPoints,
                commitments);

        logger.debug("Sending ProposalMessage to {} with id {}", Arrays.toString(context.getMembers()), context.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_PROPOSAL, serialize(proposalMessage),
                context.getMembers());
    }

    void processProposal(byte[] serializedMessage, ProposalMessage message) {
        if (proposals.size() > 2 * context.getF() + 1) {
            logger.debug("I already have {} proposals (2f + 1)", proposals.size());
            return;
        }

        byte[] cryptHash = TOMUtil.computeHash(serializedMessage);
        message.setCryptographicHash(cryptHash);
        proposals.put(Arrays.hashCode(cryptHash), message);

        if (proposals.size() > 2 * context.getF() + 1 || processId == context.getLeader())
            generateAndSendProposalSet();
    }

    private void generateAndSendProposalSet() {
        int[] receivedNodes = new int[proposals.size()];
        byte[][] receivedProposalsHashes = new byte[proposals.size()][];
        int i = 0;
        for (Map.Entry<Integer, ProposalMessage> e : proposals.entrySet()) {
            receivedNodes[i] = e.getValue().getSender();
            receivedProposalsHashes[i] = e.getValue().getCryptographicHash();
            i++;
            finalProposalSet.put(e.getKey(), e.getValue());
        }

        ProposalSetMessage proposalSetMessage =  new ProposalSetMessage(
                context.getId(),
                processId,
                receivedNodes,
                receivedProposalsHashes
        );

        logger.debug("I'm leader and I'm sending proposal set to {}", Arrays.toString(context.getMembers()));
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_PROPOSAL_SET,
                serialize(proposalSetMessage), context.getMembers());
    }

    void processProposalSet(ProposalSetMessage message) {
        invalidProposals = new LinkedList<>();
        int[] receivedNodes = message.getReceivedNodes();
        byte[][] receivedProposals = message.getReceivedProposals();
        SecretKey myKey = serversCommunication.getSecretKey(processId);

        for (int i = 0; i < receivedNodes.length; i++) {
            int proposalHash = Arrays.hashCode(receivedProposals[i]);
            ProposalMessage proposal = proposals.get(proposalHash);
            if (proposal == null) {
                logger.debug("I don't have proposal of {} with id {}", receivedNodes[i], context.getId());
                if (missingProposals == null)
                    missingProposals = new LinkedList<>();
                missingProposals.add(receivedProposals[i]);
                continue;
            }

            byte[] encryptedPoint = proposal.getEncryptedPoints()[myIndex];
            BigInteger point = decrypt(myKey, encryptedPoint);
            finalProposalSet.put(proposalHash, proposal);
            decryptedPoints.put(proposalHash, point);
            if (isInvalidPoint(point, proposal.getCommitments())) {
                logger.debug("Proposal from {} is invalid", proposal.getSender());
                invalidProposals.add(proposal.getCryptographicHash());
            }
        }

        if (missingProposals != null)
            requestMissingProposals();
        else
            sendVote();
    }

    private void sendVote() {
        byte[][] invalidProposalArray = new byte[invalidProposals.size()][];
        int counter = 0;
        for (byte[] invalidProposal : invalidProposals)
            invalidProposalArray[counter++] = invalidProposal;
        VoteMessage voteMessage = new VoteMessage(
                context.getId(),
                processId,
                invalidProposalArray
        );

        logger.debug("Sending votes to {} with id {}", context.getLeader(), context.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_VOTE, serialize(voteMessage),
                context.getLeader());
    }

    private void requestMissingProposals() {
        byte[][] missingProposalsArray = new byte[missingProposals.size()][];
        int i = 0;
        for (byte[] missingProposal : missingProposals) {
            missingProposalsArray[i++] = missingProposal;
        }

        MissingProposalRequestMessage missingProposalRequestMessage = new MissingProposalRequestMessage(
                context.getId(),
                processId,
                missingProposalsArray
        );
        logger.debug("Asking missing proposals from {} with id {}", context.getLeader(), context.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_REQUEST_MISSING_PROPOSALS,
                serialize(missingProposalRequestMessage), context.getLeader());
    }

    void generateMissingProposalsResponse(MissingProposalRequestMessage message) {
        ProposalMessage[] missingProposals = new ProposalMessage[message.getMissingProposals().length];
        for (int i = 0; i < missingProposals.length; i++) {
            int hash = Arrays.hashCode(message.getMissingProposals()[i]);
            missingProposals[i] = proposals.get(hash);
        }

        MissingProposalsMessage missingProposalsMessage = new MissingProposalsMessage(
                context.getId(),
                processId,
                missingProposals
        );
        logger.debug("Sending missing proposals to {} with id {}", message.getSender(), context.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_MISSING_PROPOSALS,
                serialize(missingProposalsMessage), message.getSender());
    }

    void processMissingProposals(MissingProposalsMessage message) {
        ProposalMessage[] missingProposals = message.getMissingProposals();
        SecretKey myKey = serversCommunication.getSecretKey(processId);

        for (ProposalMessage proposal : missingProposals) {
            byte[] serializedProposal = serialize(proposal);
            proposal.setCryptographicHash(TOMUtil.computeHash(serializedProposal));
            int proposalHash = Arrays.hashCode(proposal.getCryptographicHash());

            byte[] encryptedPoint = proposal.getEncryptedPoints()[myIndex];
            BigInteger point = decrypt(myKey, encryptedPoint);
            finalProposalSet.put(proposalHash, proposal);
            decryptedPoints.put(proposalHash, point);
            if (isInvalidPoint(point, proposal.getCommitments()))
                invalidProposals.add(proposal.getCryptographicHash());
        }

        sendVote();
    }

    boolean processVote(VoteMessage message) {
        if (processedVotesMessage != null) {
            logger.debug("I have enough votes");
            return false;
        }
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

        return acceptList.size() >= 2 * context.getF() + 1 - d;
    }

    void sendProcessedVotes() {
        processedVotesMessage =  new ProcessedVotesMessage(
                context.getId(),
                processId,
                votes
        );

        logger.debug("Sending processed votes to {} with id {}", Arrays.toString(context.getMembers()), context.getId());
        serversCommunication.sendOrdered(InterServersMessageType.POLYNOMIAL_PROCESSED_VOTES,
                serialize(processedVotesMessage), context.getMembers());
    }

    boolean processVotes(ProcessedVotesMessage message) {
        if (processedVotesMessage != null)
            return true;
        boolean terminated = false;
        for (VoteMessage vote : message.getVotes()) {
            terminated = processVote(vote);
        }
        return terminated;
    }


    void deliverResult() {
        logger.debug("I have selected {} proposals", finalProposalSet.size());
        finalProposalSet.values().forEach(p -> logger.debug("Proposal from {}", p.getSender()));

        BigInteger finalPoint = BigInteger.ZERO;
        Commitments[] allCommitments = new Commitments[finalProposalSet.size()];
        int i = 0;
        for (Map.Entry<Integer, BigInteger> e : decryptedPoints.entrySet()) {
            finalPoint = finalPoint.add(e.getValue());
            allCommitments[i++] = finalProposalSet.get(e.getKey()).getCommitments();
        }
        Share share = new Share(shareholderId, finalPoint);
        Commitments commitments = commitmentScheme.sumCommitments(allCommitments);
        VerifiableShare point =  new VerifiableShare(share, commitments, null);

        creationListener.onPolynomialCreation(context, point);
    }

    void startViewChange() {
        logger.debug("The leader {} is faulty. Changing view", context.getLeader());
    }

    private boolean isInvalidPoint(BigInteger point, Commitments commitments) {
        Share share = new Share(shareholderId, point);
        return !commitmentScheme.checkValidity(share, commitments) ||
                !commitmentScheme.checkValidity(polynomialPropertyShare, commitments); //does polynomial has the point and required property?
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
