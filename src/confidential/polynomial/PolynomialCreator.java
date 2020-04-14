package confidential.polynomial;

import bftsmart.tom.util.TOMUtil;
import confidential.Metadata;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.interServersCommunication.InterServersMessageType;
import confidential.server.ServerConfidentialityScheme;
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
    private int n;
    private final BigInteger shareholderId;
    private ProposalMessage myProposal;
    private final Map<Integer, ProposalMessage> proposals;
    private final Map<Integer, BigInteger> decryptedPoints;
    private Map<Integer, byte[]> missingProposals;
    private boolean proposalSetProposed;
    private Set<Integer> validProposals;
    private Set<Integer> invalidProposals;
    private final Share polynomialPropertyShare;
    private ServerConfidentialityScheme confidentialityScheme;
    private final PolynomialCreationListener creationListener;
    private final Set<Integer> newPolynomialRequestsFrom;

    PolynomialCreator(PolynomialContext context,
                      int processId,
                      int n, SecureRandom rndGenerator,
                      ServerConfidentialityScheme confidentialityScheme,
                      InterServersCommunication serversCommunication,
                      PolynomialCreationListener creationListener) {
        this.context = context;
        this.processId = processId;
        this.n = n;
        this.shareholderId = confidentialityScheme.getMyShareholderId();
        this.field = confidentialityScheme.getField();
        this.polynomialPropertyShare = new Share(context.getX(), context.getY());
        this.confidentialityScheme = confidentialityScheme;
        this.rndGenerator = rndGenerator;
        this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
        this.serversCommunication = serversCommunication;
        this.creationListener = creationListener;

        int maxMessages = context.getMembers().length;

        this.proposals = new HashMap<>(maxMessages);
        this.decryptedPoints = new HashMap<>(maxMessages);
        this.validProposals = new HashSet<>(maxMessages);
        this.invalidProposals = new HashSet<>(maxMessages);
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

        if (newPolynomialRequestsFrom.size() >= n - context.getF())
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
        Commitment commitments;
        if (containsShareholder(context.getMembers(), context.getX()))
            commitments = commitmentScheme.generateCommitments(polynomial);
        else //this is for allow verification of property P(0)=0 of the renewal polynomial
            commitments = commitmentScheme.generateCommitments(polynomial,
                    context.getX());
        //generating point for each member
        int[] members = context.getMembers();
        Map<Integer, byte[]> points = new HashMap<>(members.length);
        for (int member : members) {
            BigInteger point =
                    polynomial.evaluateAt(confidentialityScheme.getShareholder(member));
            byte[] encryptedPoint = confidentialityScheme.encryptDataFor(member,
                    point.toByteArray());
            points.put(member, encryptedPoint);
        }
        myProposal = new ProposalMessage(
                context.getId(),
                processId,
                points,
                commitments//commitmentScheme.extractCommitment
                // (confidentialityScheme.getShareholder(members[i]), commitments)
        );

        logger.debug("Sending ProposalMessage to {} with id {}", Arrays.toString(members),
                context.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_PROPOSAL,
                serialize(myProposal),
                members);
    }

    private boolean containsShareholder(int[] processes, BigInteger shareholder) {
        for (int process : processes) {
            if (confidentialityScheme.getShareholder(process).equals(shareholder))
                return true;
        }

        return false;
    }

    void processProposal(ProposalMessage message) {
        byte[] cryptHash = computeCryptographicHash(message);
        if (cryptHash == null)
            return;
        message.setCryptographicHash(cryptHash);
        proposals.put(message.getSender(), message);
        if (processId == context.getLeader()) {
            validateProposal(message);

            if (!proposalSetProposed && validProposals.size() > context.getF())
                generateAndSendProposalSet();
        }
    }

    private void validateProposal(ProposalMessage proposal) {
        int proposalSender = proposal.getSender();
        byte[] encryptedPoint = proposal.getPoints().get(processId);
        byte[] decryptedPoint = confidentialityScheme.decryptData(processId,
                encryptedPoint);
        if (decryptedPoint == null) {
            logger.error("Failed to decrypt my point from {}", proposal.getSender());
            return;
        }
        BigInteger point = new BigInteger(decryptedPoint);
        decryptedPoints.put(proposalSender, point);
        if (isValidPoint(point, proposal.getCommitments())) {
            validProposals.add(proposalSender);
            logger.debug("Proposal from {} is valid", proposalSender);
        } else {
            invalidProposals.add(proposalSender);
            logger.debug("Proposal from {} is invalid", proposalSender);
        }
    }

    private byte[] computeCryptographicHash(ProposalMessage message) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeInt(message.getSender());
            int[] members = new int[message.getPoints().size()];
            int i = 0;
            Map<Integer, byte[]> points = message.getPoints();
            for (int member : points.keySet()) {
                members[i++] = member;
            }
            Arrays.sort(members);
            for (int member : members) {
                out.write(member);
                out.write(points.get(member));
            }
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
        int[] receivedNodes = new int[context.getF() + 1];
        byte[][] receivedProposalsHashes = new byte[context.getF() + 1][];
        int i = 0;

        for (Integer validProposal : validProposals) {
            ProposalMessage msg = proposals.get(validProposal);
            receivedNodes[i] = msg.getSender();
            receivedProposalsHashes[i] = msg.getCryptographicHash();
            if (i == context.getF())
                break;
            i++;
        }

        ProposalSetMessage proposalSetMessage =  new ProposalSetMessage(
                context.getId(),
                processId,
                receivedNodes,
                receivedProposalsHashes
        );

        logger.debug("I'm leader and I'm proposing a proposal set with proposals from: {}",
                Arrays.toString(receivedNodes));
        serversCommunication.sendOrdered(InterServersMessageType.POLYNOMIAL_PROPOSAL_SET,
                new byte[]{(byte)Metadata.POLYNOMIAL_PROPOSAL_SET.ordinal()},
                serialize(proposalSetMessage), context.getMembers());

        proposalSetProposed = true;
    }

    private boolean isValidPoint(BigInteger point, Commitment commitment) {
        Share share = new Share(shareholderId, point);
        commitmentScheme.startVerification(commitment);
        //does polynomial has the point and required property?
        boolean isValid = commitmentScheme.checkValidity(share, commitment)
                && commitmentScheme.checkValidity(polynomialPropertyShare,
                commitment);
        commitmentScheme.endVerification();
        return isValid;
    }

    boolean isValidProposalSet(ProposalSetMessage message) {
        logger.info("Proposal set contains proposals from {}",
                Arrays.toString(message.getReceivedNodes()));
        if (processId == context.getLeader()) //leader already has verified its points
            return true;

        int[] receivedNodes = message.getReceivedNodes();
        byte[][] receivedProposals = message.getReceivedProposals();

        for (int i = 0; i < receivedNodes.length; i++) {
            int proposalSender = receivedNodes[i];
            ProposalMessage proposal = proposals.get(proposalSender);
            if (proposal == null) {
                logger.debug("I don't have proposal of {} with id {}", proposalSender,
                        context.getId());
                if (missingProposals == null)
                    missingProposals = new HashMap<>();
                missingProposals.put(proposalSender, receivedProposals[i]);
                continue;
            }

            if (!Arrays.equals(proposal.getCryptographicHash(), receivedProposals[i])) {
                logger.warn("I received different proposal from {}", proposalSender);
                return false;
            }

            if (validProposals.contains(proposalSender))
                continue;
            if (invalidProposals.contains(proposalSender))
                return false;

            validateProposal(proposal);
        }

        if (missingProposals != null) {
            requestMissingProposals();
            return false;
        } else
            return true;
    }

    private void requestMissingProposals() {
        for (Map.Entry<Integer, byte[]> e : missingProposals.entrySet()) {
            MissingProposalRequestMessage missingProposalRequestMessage = new MissingProposalRequestMessage(
                    context.getId(),
                    processId,
                    e.getValue()
            );
            logger.debug("Asking missing proposal to {} with id {}", e.getKey(), context.getId());
            serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_REQUEST_MISSING_PROPOSALS,
                    serialize(missingProposalRequestMessage), e.getKey());
        }
    }

    void generateMissingProposalsResponse(MissingProposalRequestMessage message) {
        MissingProposalsMessage missingProposalsMessage = new MissingProposalsMessage(
                context.getId(),
                processId,
                myProposal
        );
        logger.debug("Sending missing proposals to {} with id {}", message.getSender(), context.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_MISSING_PROPOSALS,
                serialize(missingProposalsMessage), message.getSender());
    }

    void processMissingProposals(MissingProposalsMessage message) {
        ProposalMessage proposal = message.getMissingProposal();
        byte[] cryptHash = computeCryptographicHash(proposal);
        proposal.setCryptographicHash(cryptHash);
        proposals.put(proposal.getSender(), proposal);

        validateProposal(proposal);
        missingProposals.remove(proposal.getSender());
    }

    void deliverResult(int consensusId, ProposalSetMessage proposalSet) {
        BigInteger finalPoint = BigInteger.ZERO;
        Commitment[] allCommitments = new Commitment[context.getF() + 1];
        int i = 0;
        List<ProposalMessage> invalidProposals = new LinkedList<>();
        for (int member : proposalSet.getReceivedNodes()) {
            ProposalMessage proposal = proposals.get(member);
            if (this.invalidProposals.contains(member))
                invalidProposals.add(proposal);
        }

        if (!invalidProposals.isEmpty()) {
            creationListener.onPolynomialCreationFailure(context, invalidProposals, consensusId);
            return;
        }

        for (int member : proposalSet.getReceivedNodes()) {
            BigInteger point = decryptedPoints.get(member);
            if (point == null) {
                creationListener.onPolynomialCreationFailure(context, invalidProposals,
                        consensusId);
                return;
            }
            finalPoint = finalPoint.add(point);
            allCommitments[i++] = proposals.get(member).getCommitments();
        }
        Share share = new Share(shareholderId, finalPoint);
        Commitment commitments = commitmentScheme.sumCommitments(allCommitments);
        VerifiableShare point =  new VerifiableShare(share,
                commitmentScheme.extractCommitment(shareholderId, commitments), null);

        creationListener.onPolynomialCreationSuccess(context, point, consensusId);
    }

    void startViewChange() {
        logger.debug("TODO:The leader {} is faulty. Changing view", context.getLeader());
        throw new UnsupportedOperationException("TODO: Implement view change in " +
                "polynomial creation");
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
