package confidential.polynomial;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.reconfiguration.views.View;
import confidential.interServersCommunication.InterServerMessageListener;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.interServersCommunication.InterServersMessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.CommitmentScheme;
import vss.secretsharing.VerifiableShare;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
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
    private int processId;
    private BigInteger shareholderId;

    public DistributedPolynomial(InterServersCommunication serversCommunication, ServerViewController svController,
                                 CommitmentScheme commitmentScheme, BigInteger field) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        this.serversCommunication = serversCommunication;
        this.svController = svController;
        this.commitmentScheme = commitmentScheme;
        this.field = field;
        this.rndGenerator = new SecureRandom(SEED);
        this.polynomialCreators = new HashMap<>();
        this.cipher = Cipher.getInstance(svController.getStaticConf().getSecretKeyAlgorithm(), svController.getStaticConf().getSecretKeyAlgorithmProvider());
        this.processId = svController.getStaticConf().getProcessId();
        this.shareholderId = BigInteger.valueOf(processId + 1);
        serversCommunication.registerListener(this, InterServersMessageType.NEW_POLYNOMIAL);
    }

    public void createNewPolynomial(int id, int f, int leader, BigInteger a, BigInteger b) {
        View view = svController.getCurrentView();
        NewPolynomialMessage newPolynomialMessage = new NewPolynomialMessage(id,
                svController.getStaticConf().getProcessId(), f, view.getId(),leader, view.getProcesses(), a, b);
        byte[] request = serialize(newPolynomialMessage);
        if (request != null) {
            logger.debug("Sending NewPolynomialMessage to {}", Arrays.toString(view.getProcesses()));
            serversCommunication.sendUnordered(InterServersMessageType.NEW_POLYNOMIAL, request, view.getProcesses());
        }
    }

    @Override
    public void messageReceived(InterServersMessageType type, byte[] message) {
        switch (type) {
            case NEW_POLYNOMIAL:
                break;
            case POLYNOMIAL_PROPOSAL:
                break;
            case POLYNOMIAL_PROPOSAL_SET:
                break;
            case POLYNOMIAL_VOTE:
                break;
            case POLYNOMIAL_MISSING_PROPOSALS:
                break;
            case POLYNOMIAL_PROCESSED_VOTES:
                break;
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
                message.getF(), rndGenerator, cipher, commitmentScheme, serversCommunication);
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
                    serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_PROPOSAL_SET, request);
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
            PolynomialMessage missingProposal = polynomialCreator.generateMissingProposalsMessage();
            byte[] request = serialize(missingProposal);
            if (request != null) {
                logger.debug("Asking missing proposals from {} with id {}", message.getLeader(), message.getId());
                serversCommunication.sendUnordered(InterServersMessageType.POLYNOMIAL_MISSING_PROPOSALS, request,
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

    private void processVotes(VoteMessage message) {
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
            logger.error("Sending processed votes to {} with id {}", Arrays.toString(message.getViewMembers()),
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
            VerifiableShare point = polynomialCreator.getFinalPoint();
            logger.debug("I have my point");
        } else {
            logger.debug("The leader {} is faulty. Changing view", message.getLeader());
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
