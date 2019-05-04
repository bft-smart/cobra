package confidential.polynomial;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.reconfiguration.views.View;
import confidential.interServersCommunication.InterServerMessageListener;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.interServersCommunication.InterServersMessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.CommitmentScheme;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class DistributedPolynomial implements InterServerMessageListener {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private static final byte[] SEED = "confidential".getBytes();

    private InterServersCommunication serversCommunication;
    private ServerViewController svController;
    private SecureRandom rndGenerator;
    private CommitmentScheme commitmentScheme;
    private BigInteger field;
    private Cipher cipher;
    private Map<Integer, PolynomialCreator> polynomialCreators;
    private Map<PolynomialCreationReason, PolynomialCreationListener> listeners;
    private int processId;
    private BigInteger shareholderId;

    public DistributedPolynomial(InterServersCommunication serversCommunication, ServerViewController svController,
                                 CommitmentScheme commitmentScheme, BigInteger field) throws NoSuchPaddingException,
            NoSuchAlgorithmException, NoSuchProviderException {
        this.serversCommunication = serversCommunication;
        this.svController = svController;
        this.commitmentScheme = commitmentScheme;
        this.field = field;
        this.rndGenerator = new SecureRandom(SEED);
        this.polynomialCreators = new HashMap<>();
        this.cipher = Cipher.getInstance("AES");//svController.getStaticConf().getSecretKeyAlgorithm(), svController.getStaticConf().getSecretKeyAlgorithmProvider());
        this.processId = svController.getStaticConf().getProcessId();
        this.shareholderId = BigInteger.valueOf(processId + 1);
        this.listeners = new HashMap<>();
        serversCommunication.registerListener(this,
                InterServersMessageType.NEW_POLYNOMIAL,
                InterServersMessageType.POLYNOMIAL_PROPOSAL,
                InterServersMessageType.POLYNOMIAL_PROPOSAL_SET,
                InterServersMessageType.POLYNOMIAL_VOTE,
                InterServersMessageType.POLYNOMIAL_REQUEST_MISSING_PROPOSALS,
                InterServersMessageType.POLYNOMIAL_MISSING_PROPOSALS,
                InterServersMessageType.POLYNOMIAL_PROCESSED_VOTES
        );
    }

    public BigInteger getShareholderId() {
        return shareholderId;
    }

    public CommitmentScheme getCommitmentScheme() {
        return commitmentScheme;
    }

    public void registerCreationListener(PolynomialCreationListener listener, PolynomialCreationReason reason) {
        listeners.put(reason, listener);
    }

    public void createNewPolynomial(int id, int f, int leader, int viewId, int[] viewMembers, BigInteger a, BigInteger b, PolynomialCreationReason reason) {
        NewPolynomialMessage newPolynomialMessage = new NewPolynomialMessage(id,
                svController.getStaticConf().getProcessId(), f, viewId,leader, viewMembers, a, b, reason);
        byte[] request = serialize(newPolynomialMessage);
        if (request != null) {
            logger.debug("Sending NewPolynomialMessage to {} with id {}", Arrays.toString(viewMembers), id);
            serversCommunication.sendUnordered(InterServersMessageType.NEW_POLYNOMIAL, request, viewMembers);
        }
    }

    @Override
    public void messageReceived(InterServersMessageType type, byte[] serializedMessage) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedMessage);
             ObjectInput in = new ObjectInputStream(bis)) {
            switch (type) {
                case NEW_POLYNOMIAL:
                    NewPolynomialMessage newPolynomialMessage = new NewPolynomialMessage();
                    newPolynomialMessage.readExternal(in);
                    generateProposal(newPolynomialMessage);
                    break;
                case POLYNOMIAL_PROPOSAL:
                    ProposalMessage proposalMessage = new ProposalMessage();
                    proposalMessage.readExternal(in);
                    processProposal(serializedMessage, proposalMessage);
                    break;
                case POLYNOMIAL_PROPOSAL_SET:
                    ProposalSetMessage proposalSetMessage = new ProposalSetMessage();
                    proposalSetMessage.readExternal(in);
                    processProposalSet(proposalSetMessage);
                    break;
                case POLYNOMIAL_VOTE:
                    VoteMessage voteMessage = new VoteMessage();
                    voteMessage.readExternal(in);
                    processVote(voteMessage);
                    break;
                case POLYNOMIAL_REQUEST_MISSING_PROPOSALS:
                    MissingProposalRequestMessage missingProposalRequestMessage = new MissingProposalRequestMessage();
                    missingProposalRequestMessage.readExternal(in);
                    sendMissingProposals(missingProposalRequestMessage);
                    break;
                case POLYNOMIAL_MISSING_PROPOSALS:
                    MissingProposalsMessage missingProposalsMessage = new MissingProposalsMessage();
                    missingProposalsMessage.readExternal(in);
                    processMissingProposals(missingProposalsMessage);
                    break;
                case POLYNOMIAL_PROCESSED_VOTES:
                    ProcessedVotesMessage processedVotesMessage = new ProcessedVotesMessage();
                    processedVotesMessage.readExternal(in);
                    processVotes(processedVotesMessage);
                    break;
            }
        } catch (IOException e) {
            logger.error("Failed to deserialize polynomial message of type {}", type, e);
        }
    }

    private void generateProposal(NewPolynomialMessage message) {
        logger.debug("Received polynomial generation message from {} with id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator != null) {
            logger.error("Received new polynomial generation message with id {} that exists", message.getId());
            return;
        }
        logger.debug("Staring new polynomial creation with id {}", message.getId());
        polynomialCreator = new PolynomialCreator(message.getId(), processId, shareholderId, field,
                message.getF(), rndGenerator, cipher, commitmentScheme, serversCommunication, listeners.get(message.getReason()));
        polynomialCreators.put(polynomialCreator.getId(), polynomialCreator);
        PolynomialMessage response = polynomialCreator.generateProposal(message);
        byte[] request = serialize(response);
        if (request != null) {
            logger.debug("Sending ProposalMessage to {} with id {}", Arrays.toString(message.getViewMembers()), response.getId());
            serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_PROPOSAL, request, message.getViewMembers());
        }
    }

    private void processProposal(byte[] serializedMessage, ProposalMessage message) {
        logger.debug("Received proposal from {} for polynomial creation id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }
        polynomialCreator.processProposal(serializedMessage, message);

        if (svController.getStaticConf().getProcessId() == message.getLeader()) {
            PolynomialMessage response = polynomialCreator.generateProposalSet();
            if (response != null) {
                byte[] request = serialize(response);
                if (request != null) {
                    logger.debug("I'm leader and I'm sending proposal set to {}", Arrays.toString(message.getViewMembers()));
                    serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_PROPOSAL_SET, request, response.getViewMembers());
                }
            }
        }
    }

    private void processProposalSet(ProposalSetMessage message) {
        logger.debug("Received proposal set from {} for polynomial creation id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }
        PolynomialMessage response = polynomialCreator.processProposalSet(message);
        if (response == null) {
            PolynomialMessage missingProposal = polynomialCreator.requestMissingProposals();
            byte[] request = serialize(missingProposal);
            if (request != null) {
                logger.debug("Asking missing proposals from {} with id {}", message.getLeader(), message.getId());
                serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_REQUEST_MISSING_PROPOSALS, request,
                        message.getLeader());
            }
        } else {
            byte[] request = serialize(response);
            if (request != null) {
                logger.debug("Sending votes to {} with id {}", message.getLeader(), message.getId());
                serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_VOTE, request, message.getLeader());
            }
        }
    }

    private void processVote(VoteMessage message) {
        logger.debug("Received vote from {} for polynomial creation id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }

        boolean terminated = polynomialCreator.processVote(message);

        if (!terminated)
            return;
        PolynomialMessage response = polynomialCreator.getProcessedVotes();
        byte[] request = serialize(response);
        if (request != null) {
            logger.debug("Sending processed votes to {} with id {}", Arrays.toString(message.getViewMembers()),
                    message.getId());
            serversCommunication.sendOrdered(InterServersMessageType.POLYNOMIAL_PROCESSED_VOTES, request, message.getViewMembers());
        }
    }

    private void processVotes(ProcessedVotesMessage message) {
        logger.debug("Received processed votes from {} for polynomial creation id {}", message.getSender(), message.getLeader());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }
        boolean terminated = polynomialCreator.processVotes(message);
        if (terminated) {
            logger.debug("I have my point");
            polynomialCreator.deliverResult();
            polynomialCreators.remove(message.getId());
        } else {
            logger.debug("The leader {} is faulty. Changing view", message.getLeader());
        }
    }

    private void sendMissingProposals(MissingProposalRequestMessage message) {
        logger.debug("Received request to send missing proposal from {} with id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }

        PolynomialMessage response = polynomialCreator.generateMissingProposalsResponse(message);
        byte[] request = serialize(response);
        if (request != null) {
            logger.debug("Sending missing proposals to {} with id {}", message.getSender(), message.getId());
            serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_MISSING_PROPOSALS, request, message.getSender());
        }
    }

    private void processMissingProposals(MissingProposalsMessage message) {
        logger.debug("Received missing proposals from {} with id {}", message.getSender(),
                message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }
        PolynomialMessage response = polynomialCreator.processMissingProposals(message);
        byte[] request = serialize(response);
        if (request != null) {
            logger.debug("Sending votes to {} with id {}", message.getLeader(), message.getId());
            serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_VOTE, request, message.getLeader());
        }
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
