package confidential.polynomial;

import bftsmart.tom.util.TOMUtil;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.interServersCommunication.InterServersMessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

class PolynomialCreator {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private PolynomialContext context;
    private final BigInteger field;
    private final SecureRandom rndGenerator;
    private final CommitmentScheme commitmentScheme;
    private final InterServersCommunication serversCommunication;
    private final int processId;
    private final BigInteger shareholderId;
    private final Map<Integer, ProposalMessage> myProposals;
    private final Map<Integer, ProposalMessage> proposals;
    private final Map<Integer, ProposalMessage> finalProposalSet;
    private final Map<Integer, BigInteger> decryptedPoints;
    private Map<Integer, byte[]> missingProposals;
    private final Share polynomialPropertyShare;
    private int d;
    private final Set<Integer> conflictList;
    private final Set<Integer> acceptList;
    private final List<VoteMessage> votes;
    private final PolynomialCreationListener creationListener;
    private List<byte[]> invalidProposals;
    private final Set<Integer> newPolynomialRequestsFrom;
    private ProcessedVotesMessage processedVotesMessage;

    PolynomialCreator(PolynomialContext context,
                      int processId,
                      BigInteger shareholderId,
                      BigInteger field,
                      SecureRandom rndGenerator,
                      CommitmentScheme commitmentScheme,
                      InterServersCommunication serversCommunication,
                      PolynomialCreationListener creationListener) {
        this.context = context;
        this.processId = processId;
        this.shareholderId = shareholderId;
        this.field = field;
        this.polynomialPropertyShare = new Share(context.getX(), context.getY());
        this.rndGenerator = rndGenerator;
        this.commitmentScheme = commitmentScheme;
        this.serversCommunication = serversCommunication;
        this.creationListener = creationListener;

        int maxMessages = context.getMembers().length;

        this.myProposals = new HashMap<>(maxMessages);
        this.proposals = new HashMap<>(maxMessages);
        this.finalProposalSet = new HashMap<>(maxMessages);
        this.decryptedPoints = new HashMap<>(maxMessages);
        this.conflictList = new HashSet<>(maxMessages);
        this.acceptList = new HashSet<>(maxMessages);
        this.votes = new ArrayList<>(maxMessages);
        this.newPolynomialRequestsFrom = new HashSet<>(maxMessages);
    }

    PolynomialContext getContext() {
        return context;
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
        if (newPolynomialRequestsFrom.size() > 2 * context.getF()) {
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
        //generating polynomial of degree f
        Polynomial tempPolynomial = new Polynomial(field, context.getF(),
                BigInteger.ZERO, rndGenerator);
        BigInteger independentTerm = polynomialPropertyShare.getShare()
                .subtract(tempPolynomial.evaluateAt(polynomialPropertyShare.getShareholder()));
        BigInteger[] tempCoefficients = tempPolynomial.getCoefficients();
        BigInteger[] coefficients = Arrays.copyOfRange(tempCoefficients,
                tempCoefficients.length - tempPolynomial.getDegree() - 1, tempCoefficients.length - 1);

        Polynomial polynomial = new Polynomial(field, independentTerm, coefficients);

        //Committing to polynomial
        Commitment commitments = commitmentScheme.generateCommitments(polynomial);

        //generating point for each member
        int[] members = context.getMembers();
        BigInteger[] points = new BigInteger[members.length];
        for (int i = 0; i < members.length; i++) {
            points[i] = polynomial.evaluateAt(BigInteger.valueOf(members[i] + 1));
        }
        for (int i = 0; i < points.length; i++) {
            ProposalMessage proposalMessage = new ProposalMessage(
                    context.getId(),
                    processId,
                    points[i],
                    commitments
            );
            myProposals.put(members[i], proposalMessage);
            logger.debug("Sending ProposalMessage to {} with id {}", members[i], context.getId());
            serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_PROPOSAL, serialize(proposalMessage),
                    members[i]);
        }

    }

    void processProposal(ProposalMessage message) {
        if (proposals.size() > 2 * context.getF()) {
            logger.debug("I already have {} proposals (2f + 1)", proposals.size());
        }

        byte[] cryptHash = computeCryptographicHash(message);
        if (cryptHash == null)
            return;
        message.setCryptographicHash(cryptHash);
        int hash = Arrays.hashCode(cryptHash);
        proposals.put(hash, message);

        if (proposals.size() == 2 * context.getF() + 1 && processId == context.getLeader())
            generateAndSendProposalSet();
    }

    private byte[] computeCryptographicHash(ProposalMessage message) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeInt(message.getSender());
            message.getCommitments().writeExternal(out);
            out.flush();
            bos.flush();
            return TOMUtil.computeHash(bos.toByteArray());
        } catch (IOException e) {
            logger.error("Failed to create cryptographic hash of the proposal from {}", message.getSender(), e);
            return null;
        }
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

        for (int i = 0; i < receivedNodes.length; i++) {
            int proposalHash = Arrays.hashCode(receivedProposals[i]);
            ProposalMessage proposal = proposals.get(proposalHash);
            if (proposal == null) {
                logger.debug("I don't have proposal of {} with id {}", receivedNodes[i], context.getId());
                if (missingProposals == null)
                    missingProposals = new HashMap<>();
                missingProposals.put(receivedNodes[i], receivedProposals[i]);
                continue;
            }


            BigInteger point = proposal.getPoint();
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
        for (Map.Entry<Integer, byte[]> e : missingProposals.entrySet()) {
            MissingProposalRequestMessage missingProposalRequestMessage = new MissingProposalRequestMessage(
                    context.getId(),
                    processId,
                    e.getValue()
            );
            logger.debug("Asking missing proposals to {} with id {}", e.getKey(), context.getId());
            serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_REQUEST_MISSING_PROPOSALS,
                    serialize(missingProposalRequestMessage), e.getKey());
        }
    }

    void generateMissingProposalsResponse(MissingProposalRequestMessage message) {
        ProposalMessage proposal = myProposals.get(message.getSender());
        if (proposal == null) {
            logger.debug("I do not have proposal requested by {}", message.getSender());
            return;
        }

        MissingProposalsMessage missingProposalsMessage = new MissingProposalsMessage(
                context.getId(),
                processId,
                proposal
        );
        logger.debug("Sending missing proposals to {} with id {}", message.getSender(), context.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_MISSING_PROPOSALS,
                serialize(missingProposalsMessage), message.getSender());
    }

    void processMissingProposals(MissingProposalsMessage message) {
        ProposalMessage proposal = message.getMissingProposal();
        byte[] cryptoHash = computeCryptographicHash(proposal);
        proposal.setCryptographicHash(cryptoHash);
        int proposalHash = Arrays.hashCode(cryptoHash);

        BigInteger point = proposal.getPoint();
        finalProposalSet.put(proposalHash, proposal);
        decryptedPoints.put(proposalHash, point);
        if (isInvalidPoint(point, proposal.getCommitments()))
            invalidProposals.add(proposal.getCryptographicHash());

        missingProposals.remove(proposal.getSender());
        if (missingProposals.isEmpty())
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


    void deliverResult(int consensusId) {
        logger.debug("I have selected {} proposals", finalProposalSet.size());
        finalProposalSet.values().forEach(p -> logger.debug("Proposal from {}", p.getSender()));

        BigInteger finalPoint = BigInteger.ZERO;
        Commitment[] allCommitments = new Commitment[finalProposalSet.size()];
        int i = 0;
        for (Map.Entry<Integer, BigInteger> e : decryptedPoints.entrySet()) {
            finalPoint = finalPoint.add(e.getValue());
            allCommitments[i++] = finalProposalSet.get(e.getKey()).getCommitments();
        }
        Share share = new Share(shareholderId, finalPoint);
        Commitment commitments = commitmentScheme.sumCommitments(allCommitments);
        VerifiableShare point =  new VerifiableShare(share, commitments, null);

        creationListener.onPolynomialCreation(context, point, consensusId);
    }

    void startViewChange() {
        logger.debug("TODO:The leader {} is faulty. Changing view", context.getLeader());
    }

    private boolean isInvalidPoint(BigInteger point, Commitment commitments) {
        Share share = new Share(shareholderId, point);
        commitmentScheme.startVerification(commitments);
        boolean isValid = !commitmentScheme.checkValidity(share, commitments) ||
                !commitmentScheme.checkValidity(polynomialPropertyShare, commitments); //does polynomial has the point and required property?
        commitmentScheme.endVerification();
        return isValid;
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
}
