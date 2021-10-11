package confidential.polynomial.creator;

import bftsmart.tom.util.TOMUtil;
import confidential.Configuration;
import confidential.Metadata;
import confidential.interServersCommunication.CommunicationTag;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.interServersCommunication.InterServersMessageType;
import confidential.polynomial.*;
import confidential.server.ServerConfidentialityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.linear.LinearCommitments;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public abstract class PolynomialCreator {
    protected Logger logger = LoggerFactory.getLogger("polynomial_generation");
    protected final PolynomialCreationContext creationContext;
    private final int quorumThreshold;
    protected final int faultsThreshold;
    protected final BigInteger field;
    protected final SecureRandom rndGenerator;
    protected final CommitmentScheme commitmentScheme;
    private final InterServersCommunication serversCommunication;
    protected final int processId;
    protected final BigInteger shareholderId;
    private ProposalMessage myProposal;
    protected final ConcurrentHashMap<Integer, ProposalMessage> proposals;
    protected final ConcurrentHashMap<Integer, BigInteger[]> decryptedPoints;
    private ConcurrentHashMap<Integer, byte[]> missingProposals;
    private boolean proposalSetProposed;
    protected final Set<Integer> validProposals;
    protected final Set<Integer> invalidProposals;
    protected final ServerConfidentialityScheme confidentialityScheme;
    protected final PolynomialCreationListener creationListener;
    private final Set<Integer> newPolynomialRequestsFrom;
    protected final int[] allMembers;
    protected final DistributedPolynomial distributedPolynomial;
    private boolean iHaveSentNewPolyRequest;
    private final Lock lock;
    private final BigInteger p;
    private final Lock proposalSetLock = new ReentrantLock(true);
    private final Condition waitingMissingProposalsCondition = proposalSetLock.newCondition();

    PolynomialCreator(PolynomialCreationContext creationContext,
                      int processId, SecureRandom rndGenerator,
                      ServerConfidentialityScheme confidentialityScheme,
                      InterServersCommunication serversCommunication,
                      PolynomialCreationListener creationListener,
                      int n,
                      int f, DistributedPolynomial distributedPolynomial) {
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
        this.distributedPolynomial = distributedPolynomial;
        this.quorumThreshold = n - f;
        this.faultsThreshold = f;

        this.lock = new ReentrantLock(true);

        int maxMessages = creationContext.getContexts()[0].getMembers().length;

        this.proposals = new ConcurrentHashMap<>(maxMessages);
        this.decryptedPoints = new ConcurrentHashMap<>(maxMessages);
        this.validProposals = ConcurrentHashMap.newKeySet(maxMessages);
        this.invalidProposals = ConcurrentHashMap.newKeySet(maxMessages);
        this.newPolynomialRequestsFrom = ConcurrentHashMap.newKeySet(maxMessages);
        this.p = new BigInteger(Configuration.getInstance().getPrimeField(), 16);
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

    public void messageReceived(InterServersMessageType type, PolynomialMessage message, int cid) {
        switch (type) {
            case NEW_POLYNOMIAL:
                processNewPolynomialMessage((NewPolynomialMessage) message);
                break;
            case POLYNOMIAL_PROPOSAL:
                processProposal((ProposalMessage) message);
                break;
            case POLYNOMIAL_PROPOSAL_SET:
                deliverResult(cid, (ProposalSetMessage) message);
                distributedPolynomial.removePolynomialCreator(creationContext.getId());
                break;
            case POLYNOMIAL_REQUEST_MISSING_PROPOSALS:
                generateMissingProposalsResponse((MissingProposalRequestMessage) message);
                break;
            case POLYNOMIAL_MISSING_PROPOSALS:
                processMissingProposals((MissingProposalsMessage) message);
                break;
        }
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
        serversCommunication.sendUnordered(CommunicationTag.POLYNOMIAL, InterServersMessageType.NEW_POLYNOMIAL,
                serialize(newPolynomialMessage), members);
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
        lock.lock();
        if (myProposal == null && newPolynomialRequestsFrom.size() >= quorumThreshold)
            generateAndSendProposal();
        lock.unlock();
    }

    private void generateAndSendProposal() {
        myProposal = computeProposalMessage();

        byte[] proposalHash = computeCryptographicHash(myProposal);
        PrivateKey signingKey = confidentialityScheme.getSigningPrivateKey();
        byte[] signature = TOMUtil.signMessage(signingKey, proposalHash);
        myProposal.setSignature(signature);

        int[] members = getMembers(false);
        logger.debug("Sending ProposalMessage to {} with id {}", Arrays.toString(members),
                creationContext.getId());
        serversCommunication.sendUnordered(CommunicationTag.POLYNOMIAL, InterServersMessageType.POLYNOMIAL_PROPOSAL,
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
            lock.lock();
            if (!proposalSetProposed && validProposals.size() > faultsThreshold)
                generateAndSendProposalSet();
            lock.unlock();
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

        Iterator<Map.Entry<Integer, ProposalMessage>> it = proposals.entrySet().iterator();
        CountDownLatch latch = new CountDownLatch(faultsThreshold + 1);
        for (int i = 0; i < receivedNodes.length; i++) {
            Map.Entry<Integer, ProposalMessage> entry = it.next();
            int finalI = i;
            distributedPolynomial.submitJob(() -> {
                if (invalidProposals.contains(entry.getKey())) {
                    return;
                }
                ProposalMessage proposal = entry.getValue();
                if (validProposals.contains(entry.getKey())) {
                    receivedNodes[finalI] = proposal.getSender();
                    receivedProposalsHashes[finalI] = proposal.getCryptographicHash();
                } else if (validateProposal(proposal)) {
                    receivedNodes[finalI] = proposal.getSender();
                    receivedProposalsHashes[finalI] = proposal.getCryptographicHash();
                }
                latch.countDown();
            });
        }

        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        ProposalSetMessage proposalSetMessage =  new ProposalSetMessage(
                creationContext.getId(),
                processId,
                receivedNodes,
                receivedProposalsHashes
        );
        int[] members = getMembers(false);
        logger.debug("I'm leader for {} and I'm proposing a proposal set with proposals from: {}",
                creationContext.getId(), Arrays.toString(receivedNodes));
        serversCommunication.sendOrdered(InterServersMessageType.POLYNOMIAL_PROPOSAL_SET,
                new byte[]{(byte)Metadata.POLYNOMIAL_PROPOSAL_SET.ordinal()},
                serialize(proposalSetMessage), members);

        proposalSetProposed = true;
    }

    public boolean isValidProposalSet(ProposalSetMessage message) {
        logger.debug("Proposal set for {} contains proposals from {}", message.getId(),
                Arrays.toString(message.getReceivedNodes()));
        if (processId == creationContext.getLeader()) //leader already has verified its points
            return true;

        int[] receivedNodes = message.getReceivedNodes();
        byte[][] receivedProposals = message.getReceivedProposals();

        LinkedList<Integer> missingProposalIndexes = new LinkedList<>();

        AtomicBoolean isValid = new AtomicBoolean(true);
        CountDownLatch latch = new CountDownLatch(receivedNodes.length);
        for (int i = 0; i < receivedNodes.length; i++) {
            int proposalSender = receivedNodes[i];
            byte[] receivedProposalHash = receivedProposals[i];
            ProposalMessage proposal = proposals.get(proposalSender);
            if (proposal == null) {
                logger.debug("I don't have proposal of {} with id {}", proposalSender,
                        creationContext.getId());
                missingProposalIndexes.add(i);
                latch.countDown();
                continue;
            }
            checkSelectedProposal(isValid, latch, proposalSender, receivedProposalHash, proposal);
        }

        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        if (!isValid.get()) {
            return false;
        }
        if (!missingProposalIndexes.isEmpty()) {
            if (missingProposals == null) {
                missingProposals = new ConcurrentHashMap<>();
            }
            for (int proposalIndex : missingProposalIndexes) {
                int proposalSender = receivedNodes[proposalIndex];
                byte[] receivedProposalHash = receivedProposals[proposalIndex];
                missingProposals.put(proposalSender, receivedProposalHash);
            }

            requestMissingProposals();
            try {
                proposalSetLock.lock();
                waitingMissingProposalsCondition.await();
            } catch (InterruptedException e) {
                e.printStackTrace();
            } finally {
                proposalSetLock.unlock();
            }
            CountDownLatch missingProposalsLatch = new CountDownLatch(missingProposalIndexes.size());
            for (Integer missingProposalIndex : missingProposalIndexes) {
                int proposalSender = receivedNodes[missingProposalIndex];
                byte[] receivedProposalHash = receivedProposals[missingProposalIndex];
                ProposalMessage proposal = proposals.get(proposalSender);
                if (proposal == null) {
                    logger.error("I still don't have proposal of {} with id {}. Responding false.", proposalSender,
                            creationContext.getId());
                    return false;
                }
                checkSelectedProposal(isValid, missingProposalsLatch, proposalSender, receivedProposalHash, proposal);
            }
            try {
                missingProposalsLatch.await();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        return isValid.get();
    }

    private void checkSelectedProposal(AtomicBoolean isValid, CountDownLatch latch, int proposalSender,
                                       byte[] receivedProposalHash, ProposalMessage proposal) {
        distributedPolynomial.submitProposalVerificationJob(() -> {
            if (!Arrays.equals(proposal.getCryptographicHash(), receivedProposalHash)) {
                logger.warn("I received different proposal from {}", proposalSender);
                isValid.set(false);
            } else {
                if (!validProposals.contains(proposalSender)) {
                    if (invalidProposals.contains(proposalSender)) {
                        isValid.set(false);
                    } else if (!validateProposal(proposal)) {
                        isValid.set(false);
                    }
                }
            }
            latch.countDown();
        });
    }

    private void requestMissingProposals() {
        for (Map.Entry<Integer, byte[]> e : missingProposals.entrySet()) {
            MissingProposalRequestMessage missingProposalRequestMessage = new MissingProposalRequestMessage(
                    creationContext.getId(),
                    processId,
                    e.getValue()
            );
            logger.debug("Asking missing proposal to {} with id {}", e.getKey(), creationContext.getId());
            serversCommunication.sendUnordered(CommunicationTag.POLYNOMIAL, InterServersMessageType.POLYNOMIAL_REQUEST_MISSING_PROPOSALS,
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
        serversCommunication.sendUnordered(CommunicationTag.POLYNOMIAL, InterServersMessageType.POLYNOMIAL_MISSING_PROPOSALS,
                serialize(missingProposalsMessage), message.getSender());
    }

    public void processMissingProposals(MissingProposalsMessage message) {
        logger.debug("Received missing proposal from {} with id {}", message.getSender(), message.getId());
        ProposalMessage proposal = message.getMissingProposal();
        byte[] cryptHash = computeCryptographicHash(proposal);
        proposal.setCryptographicHash(cryptHash);
        proposals.put(proposal.getSender(), proposal);

        validateProposal(proposal);
        missingProposals.remove(proposal.getSender());
        if (missingProposals.isEmpty()) {
            proposalSetLock.lock();
            waitingMissingProposalsCondition.signal();
            proposalSetLock.unlock();
        }
    }

    public void deliverResult(int consensusId, ProposalSetMessage proposalSet) {
        boolean useMatrix = creationContext.useVandermondeMatrix();
        BigInteger[][] finalPoint = null;
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
                if (useMatrix) {
                    finalPoint = new BigInteger[nPolynomials][faultsThreshold + 1];
                } else {
                    finalPoint = new BigInteger[nPolynomials][1];
                    for (int j = 0; j < finalPoint.length; j++) {
                        finalPoint[j][0] = BigInteger.ZERO;
                    }
                }
                allCommitments = new Commitment[nPolynomials][faultsThreshold + 1];
            }
            for (int j = 0; j < finalPoint.length; j++) {
                if (useMatrix) {
                    finalPoint[j][i] = points[j];
                } else {
                    finalPoint[j][0] = finalPoint[j][0].add(points[j]);
                }
                allCommitments[j][i] = proposals.get(member).getProposals()[j].getCommitments();
            }
            i++;
        }
        if (finalPoint == null) {
            logger.error("Something went wrong while computing final point");
            return;
        }
        VerifiableShare[][] result;
        if (useMatrix) {
            result = new VerifiableShare[finalPoint.length][faultsThreshold + 1];
            for (int j = 0; j < finalPoint.length; j++) {
                result[j] = computeResultUsingVandermondeMatrix(finalPoint[j], allCommitments[j],
                        creationContext.combineCommitments());
            }
        } else {
            result = new VerifiableShare[finalPoint.length][1];
            for (int j = 0; j < finalPoint.length; j++) {
                Share share = new Share(shareholderId, finalPoint[j][0]);
                Commitment commitments = null;
                try {
                    commitments = commitmentScheme.sumCommitments(allCommitments[j]);
                } catch (SecretSharingException e) {
                    logger.error("Failed to combine commitments", e);
                }
                result[j][0] =  new VerifiableShare(share,
                        commitmentScheme.extractCommitment(shareholderId, commitments), null);
            }
        }
        creationListener.onPolynomialCreationSuccess(creationContext, consensusId, result);
    }

    private VerifiableShare[] computeResultUsingVandermondeMatrix(BigInteger[] points, Commitment[] commitments,
                                                        boolean combineCommitments) {
        logger.debug("Using vandermonde matrix for polynomial creation {}", creationContext.getId());
        BigInteger[][] vandermondeMatrix = distributedPolynomial.getVandermondeMatrix();
        int rows = vandermondeMatrix.length;
        int columns = vandermondeMatrix[0].length;
        VerifiableShare[] result = new VerifiableShare[vandermondeMatrix.length];
        Commitment resultCommitment;
        BigInteger[] linearCommitments;

        for (int r = 0; r < rows; r++) {
            BigInteger temp = BigInteger.ZERO;
            linearCommitments = new BigInteger[faultsThreshold + 1];
            Arrays.fill(linearCommitments, BigInteger.ONE);
            for (int c = 0; c < columns; c++) {
                temp = temp.add(vandermondeMatrix[r][c].multiply(points[c])).mod(field);
                if (combineCommitments) {
                    BigInteger x = vandermondeMatrix[r][c];
                    BigInteger[] tempC = ((LinearCommitments) commitments[c]).getCommitments();
                    for (int i = 0; i < tempC.length; i++) {
                        linearCommitments[i] = linearCommitments[i].multiply(tempC[i].modPow(x, p)).mod(p);
                    }
                }
            }
            if (combineCommitments) {
                resultCommitment = new LinearCommitments(linearCommitments);
            } else {
                resultCommitment = commitments[r];
            }
            result[r] = new VerifiableShare(new Share(shareholderId, temp), resultCommitment, null);
        }

        return result;
    }

    private byte[] serialize(PolynomialMessage message) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            if (message instanceof ProposalMessage)
                confidentialityScheme.serializeProposalMessage((ProposalMessage) message, out);
            else if (message instanceof MissingProposalsMessage)
                confidentialityScheme.serializeMissingProposalMessage((MissingProposalsMessage)message, out);
            else
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
