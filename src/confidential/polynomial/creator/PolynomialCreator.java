package confidential.polynomial.creator;

import bftsmart.tom.util.TOMUtil;
import confidential.Metadata;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.interServersCommunication.InterServersMessageType;
import confidential.polynomial.*;
import confidential.server.ServerConfidentialityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.*;

public abstract class PolynomialCreator {
    protected Logger logger = LoggerFactory.getLogger("confidential");
    protected final PolynomialCreationContext creationContext;
    private final int quorumThreshold;
    private final int faultsThreshold;
    protected final BigInteger field;
    protected final SecureRandom rndGenerator;
    protected final CommitmentScheme commitmentScheme;
    private final InterServersCommunication serversCommunication;
    protected final int processId;
    protected final BigInteger shareholderId;
    private ProposalMessage myProposal;
    private final Map<Integer, ProposalMessage> proposals;
    protected final Map<Integer, BigInteger[]> decryptedPoints;
    private Map<Integer, byte[]> missingProposals;
    private boolean proposalSetProposed;
    protected final Set<Integer> validProposals;
    protected final Set<Integer> invalidProposals;
    protected final ServerConfidentialityScheme confidentialityScheme;
    private final PolynomialCreationListener creationListener;
    private final Set<Integer> newPolynomialRequestsFrom;
    protected final int[] allMembers;
    private boolean iHaveSentNewPolyRequest;
    private long startTime;

    PolynomialCreator(PolynomialCreationContext creationContext,
                      int processId, SecureRandom rndGenerator,
                      ServerConfidentialityScheme confidentialityScheme,
                      InterServersCommunication serversCommunication,
                      PolynomialCreationListener creationListener,
                      int n,
                      int f) {
        this.creationContext = creationContext;
        this.processId = processId;
        this.shareholderId = confidentialityScheme.getMyShareholderId();
        this.field = confidentialityScheme.getField();
        this.confidentialityScheme = confidentialityScheme;
        this.rndGenerator = rndGenerator;
        this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
        this.serversCommunication = serversCommunication;
        this.creationListener = creationListener;

        this.allMembers = computeAllUniqueMembers(creationContext);
        this.quorumThreshold = n - f;
        this.faultsThreshold = f;

        int maxMessages = creationContext.getContexts()[0].getMembers().length;

        this.proposals = new HashMap<>(maxMessages);
        this.decryptedPoints = new HashMap<>(maxMessages);
        this.validProposals = new HashSet<>(maxMessages);
        this.invalidProposals = new HashSet<>(maxMessages);
        this.newPolynomialRequestsFrom = new HashSet<>(maxMessages);
    }

    private static int[] computeAllUniqueMembers(PolynomialCreationContext creationContext) {
        int totalMembers = 0;
        for (PolynomialContext context : creationContext.getContexts()) {
            totalMembers += context.getMembers().length;
        }

        HashSet<Integer> uniqueMembers = new HashSet<>(totalMembers);
        for (PolynomialContext context : creationContext.getContexts()) {
            for (int member : context.getMembers()) {
                uniqueMembers.add(member);
            }
        }
        int index = 0;
        int[] allMembers = new int[uniqueMembers.size()];
        for (Integer uniqueMember : uniqueMembers) {
            allMembers[index++] = uniqueMember;
        }
        return allMembers;
    }

    public PolynomialCreationContext getCreationContext() {
        return creationContext;
    }

    abstract int[] getMembers(boolean proposalMembers);

    public void sendNewPolynomialCreationRequest() {
        if (iHaveSentNewPolyRequest)
            return;
        NewPolynomialMessage newPolynomialMessage = new NewPolynomialMessage(
                processId, creationContext);
        int[] members = getMembers(true);
        logger.debug("Sending NewPolynomialMessage to {} with id {}", Arrays.toString(members),
                creationContext.getId());
        serversCommunication.sendUnordered(InterServersMessageType.NEW_POLYNOMIAL, serialize(newPolynomialMessage),
                members);
        iHaveSentNewPolyRequest = true;
    }

    public void processNewPolynomialMessage(NewPolynomialMessage newPolynomialMessage) {
        if (newPolynomialRequestsFrom.size() >= quorumThreshold) {
            logger.debug("I already have n-f new polynomial Messages");
            return;
        }

        if (newPolynomialRequestsFrom.contains(newPolynomialMessage.getSender())) {
            logger.debug("Duplicated new polynomial request from {} with id {}",
                    newPolynomialMessage.getSender(), newPolynomialMessage.getId());
            return;
        }

        if (!creationContext.equals(newPolynomialMessage.getContext())) {
            logger.debug("New polynomial message from {} with id {} has different context",
                    newPolynomialMessage.getSender(),
                    newPolynomialMessage.getId());
            return;
        }

        newPolynomialRequestsFrom.add(newPolynomialMessage.getSender());

        logger.debug("I have {} requests to start creation of new polynomial with id {}",
                newPolynomialRequestsFrom.size(), creationContext.getId());

        if (newPolynomialRequestsFrom.size() >= quorumThreshold)
            generateAndSendProposal();
    }

    private void generateAndSendProposal() {
        startTime = System.nanoTime();
        myProposal = computeProposalMessage();

        byte[] proposalHash = computeCryptographicHash(myProposal);
        PrivateKey signingKey = confidentialityScheme.getSigningPrivateKey();
        byte[] signature = TOMUtil.signMessage(signingKey, proposalHash);
        myProposal.setSignature(signature);

        int[] members = getMembers(false);
        logger.debug("Sending ProposalMessage to {} with id {}", Arrays.toString(members),
                creationContext.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_PROPOSAL,
                serialize(myProposal), members);
    }

    abstract ProposalMessage computeProposalMessage();

    Map<Integer, byte[]> computeShares(Polynomial polynomial, int[] members) {
        Map<Integer, byte[]> points = new HashMap<>(members.length);
        for (int member : members) {
            BigInteger point =
                    polynomial.evaluateAt(confidentialityScheme.getShareholder(member));

            byte[] encryptedPoint = confidentialityScheme.encryptDataFor(member,
                    point.toByteArray());
            points.put(member, encryptedPoint);
        }
        return points;
    }

    public void processProposal(ProposalMessage message) {
        if (proposals.containsKey(message.getSender())) {
            logger.warn("Duplicate proposal from {}. Ignoring.", message.getSender());
            return;
        }
        byte[] cryptHash = computeCryptographicHash(message);
        if (cryptHash == null) {
            return;
        }
        PublicKey signingPublicKey = confidentialityScheme.getSigningPublicKeyFor(message.getSender());
        if (!TOMUtil.verifySignature(signingPublicKey, cryptHash, message.getSignature())) {
            logger.warn("Server {} sent me a proposal with an invalid signature. Ignoring.", message.getSender());
            return;
        }
        message.setCryptographicHash(cryptHash);
        proposals.put(message.getSender(), message);
        if (processId == creationContext.getLeader()) {
            validateProposal(message);

            if (!proposalSetProposed && validProposals.size() > faultsThreshold)
                generateAndSendProposalSet();
        }
    }

    abstract boolean validateProposal(ProposalMessage proposalMessage);

    private byte[] computeCryptographicHash(ProposalMessage message) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeInt(message.getSender());
            out.writeInt(message.getId());
            for (Proposal proposal : message.getProposals()) {
                int[] members = new int[proposal.getPoints().size()];
                int i = 0;
                Map<Integer, byte[]> points = proposal.getPoints();
                for (int member : points.keySet()) {
                    members[i++] = member;
                }
                Arrays.sort(members);
                for (int member : members) {
                    out.write(member);
                    out.write(points.get(member));
                }
                proposal.getCommitments().writeExternal(out);
            }
            out.flush();
            bos.flush();
            return TOMUtil.computeHash(bos.toByteArray());
        } catch (IOException e) {
            logger.error("Failed to create cryptographic hash of the proposal from {}", message.getSender(), e);
            return null;
        }
    }

    private void generateAndSendProposalSet() {
        int[] receivedNodes = new int[faultsThreshold + 1];
        byte[][] receivedProposalsHashes = new byte[faultsThreshold + 1][];
        int i = 0;

        for (Map.Entry<Integer, ProposalMessage> entry : proposals.entrySet()) {
            if (invalidProposals.contains(entry.getKey()))
                continue;
            ProposalMessage proposal = entry.getValue();
            if (validProposals.contains(entry.getKey())) {
                receivedNodes[i] = proposal.getSender();
                receivedProposalsHashes[i] = proposal.getCryptographicHash();
            } else if (validateProposal(proposal)) {
                receivedNodes[i] = proposal.getSender();
                receivedProposalsHashes[i] = proposal.getCryptographicHash();
            }
            if (i == faultsThreshold)
                break;
            i++;
        }

        ProposalSetMessage proposalSetMessage =  new ProposalSetMessage(
                creationContext.getId(),
                processId,
                receivedNodes,
                receivedProposalsHashes
        );
        int[] members = getMembers(false);
        logger.debug("I'm leader and I'm proposing a proposal set with proposals from: {}",
                Arrays.toString(receivedNodes));
        serversCommunication.sendOrdered(InterServersMessageType.POLYNOMIAL_PROPOSAL_SET,
                new byte[]{(byte)Metadata.POLYNOMIAL_PROPOSAL_SET.ordinal()},
                serialize(proposalSetMessage), members);

        proposalSetProposed = true;
    }

    boolean isValidShare(Commitment commitment, Share... shares) {
        boolean isValid = true;
        commitmentScheme.startVerification(commitment);
        for (Share share : shares) {
            if (!commitmentScheme.checkValidity(share, commitment)) {
                isValid = false;
                break;
            }
        }
        commitmentScheme.endVerification();
        return isValid;
    }

    public boolean isValidProposalSet(ProposalSetMessage message) {
        logger.info("Proposal set contains proposals from {}",
                Arrays.toString(message.getReceivedNodes()));
        if (processId == creationContext.getLeader()) //leader already has verified its points
            return true;

        int[] receivedNodes = message.getReceivedNodes();
        byte[][] receivedProposals = message.getReceivedProposals();

        for (int i = 0; i < receivedNodes.length; i++) {
            int proposalSender = receivedNodes[i];
            ProposalMessage proposal = proposals.get(proposalSender);
            if (proposal == null) {
                logger.debug("I don't have proposal of {} with id {}", proposalSender,
                        creationContext.getId());
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

            if (!validateProposal(proposal))
                return false;
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
                    creationContext.getId(),
                    processId,
                    e.getValue()
            );
            logger.debug("Asking missing proposal to {} with id {}", e.getKey(), creationContext.getId());
            serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_REQUEST_MISSING_PROPOSALS,
                    serialize(missingProposalRequestMessage), e.getKey());
        }
    }

    public void generateMissingProposalsResponse(MissingProposalRequestMessage message) {
        MissingProposalsMessage missingProposalsMessage = new MissingProposalsMessage(
                creationContext.getId(),
                processId,
                myProposal
        );
        logger.debug("Sending missing proposals to {} with id {}", message.getSender(), creationContext.getId());
        serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_MISSING_PROPOSALS,
                serialize(missingProposalsMessage), message.getSender());
    }

    public void processMissingProposals(MissingProposalsMessage message) {
        ProposalMessage proposal = message.getMissingProposal();
        byte[] cryptHash = computeCryptographicHash(proposal);
        proposal.setCryptographicHash(cryptHash);
        proposals.put(proposal.getSender(), proposal);

        validateProposal(proposal);
        missingProposals.remove(proposal.getSender());
    }

    public void deliverResult(int consensusId, ProposalSetMessage proposalSet) {
        BigInteger[] finalPoint = null;
        Commitment[][] allCommitments = null;
        int i = 0;
        List<ProposalMessage> invalidProposals = new LinkedList<>();
        for (int member : proposalSet.getReceivedNodes()) {
            ProposalMessage proposal = proposals.get(member);
            if (this.invalidProposals.contains(member))
                invalidProposals.add(proposal);
        }

        if (!invalidProposals.isEmpty()) {
            creationListener.onPolynomialCreationFailure(creationContext, invalidProposals, consensusId);
            return;
        }

        for (int member : proposalSet.getReceivedNodes()) {
            BigInteger[] points = decryptedPoints.get(member);
            if (points == null) { //if this replica did not received some proposals
                creationListener.onPolynomialCreationFailure(creationContext, invalidProposals,
                        consensusId);
                return;
            }
            if (finalPoint == null) {
                int nPolynomials = points.length;
                finalPoint = new BigInteger[nPolynomials];
                Arrays.fill(finalPoint, BigInteger.ZERO);
                allCommitments = new Commitment[nPolynomials][faultsThreshold + 1];
            }
            for (int j = 0; j < finalPoint.length; j++) {
                finalPoint[j] = finalPoint[j].add(points[j]);
                allCommitments[j][i] = proposals.get(member).getProposals()[j].getCommitments();
            }
            i++;
        }
        if (finalPoint == null) {
            logger.error("Something went wrong while computing final point");
            return;
        }
        VerifiableShare[] result = new VerifiableShare[finalPoint.length];
        for (int j = 0; j < finalPoint.length; j++) {
            Share share = new Share(shareholderId, finalPoint[j]);
            Commitment commitments = null;
            try {
                commitments = commitmentScheme.sumCommitments(allCommitments[j]);
            } catch (SecretSharingException e) {
                logger.error("Failed to combine commitments", e);
            }
            result[j] =  new VerifiableShare(share,
                    commitmentScheme.extractCommitment(shareholderId, commitments), null);
        }
        long endTime = System.nanoTime();
        double totalTime = (endTime - startTime) / 1_000_000.0;
        logger.info("{}: Polynomial {} creation time: {} ms", creationContext.getReason(), creationContext.getId(), totalTime);
        creationListener.onPolynomialCreationSuccess(creationContext, consensusId, result);
    }

    public void startViewChange() {
        logger.debug("TODO:The leader {} is faulty. Changing view", creationContext.getLeader());
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
            return null;
        }
    }

    protected BigInteger getRandomNumber() {
        BigInteger rndBig = new BigInteger(field.bitLength() - 1, rndGenerator);
        if (rndBig.compareTo(BigInteger.ZERO) == 0) {
            rndBig = rndBig.add(BigInteger.ONE);
        }

        return rndBig;
    }
}
