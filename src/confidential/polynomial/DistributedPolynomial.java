package confidential.polynomial;

import confidential.interServersCommunication.InterServerMessageHolder;
import confidential.interServersCommunication.InterServerMessageListener;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.interServersCommunication.InterServersMessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.CommitmentScheme;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DistributedPolynomial implements InterServerMessageListener, Runnable {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private static final byte[] SEED = "confidential".getBytes();

    private InterServersCommunication serversCommunication;
    private SecureRandom rndGenerator;
    private CommitmentScheme commitmentScheme;
    private BigInteger field;
    private Cipher cipher;
    private Map<Integer, PolynomialCreator> polynomialCreators;//TODO should I change to concurrentMap?
    private Map<PolynomialCreationReason, PolynomialCreationListener> listeners;//TODO should I change to concurrentMap?
    private int processId;
    private BigInteger shareholderId;
    private int lastPolynomialCreationProcessed;
    private BlockingQueue<InterServerMessageHolder> pendingMessages;
    private Lock entryLock;

    public DistributedPolynomial(int processId, InterServersCommunication serversCommunication,
                                 CommitmentScheme commitmentScheme, BigInteger field) throws NoSuchPaddingException,
            NoSuchAlgorithmException {
        this.serversCommunication = serversCommunication;
        this.commitmentScheme = commitmentScheme;
        this.field = field;
        this.rndGenerator = new SecureRandom(SEED);
        this.polynomialCreators = new HashMap<>();
        this.cipher = Cipher.getInstance("AES");//svController.getStaticConf().getSecretKeyAlgorithm(), svController.getStaticConf().getSecretKeyAlgorithmProvider());
        this.processId = processId;
        this.shareholderId = BigInteger.valueOf(processId + 1);
        this.listeners = new HashMap<>();
        this.lastPolynomialCreationProcessed = -1;
        this.pendingMessages = new LinkedBlockingQueue<>();
        entryLock = new ReentrantLock(true);
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

    public void registerCreationListener(PolynomialCreationListener listener, PolynomialCreationReason reason) {
        entryLock.lock();
        listeners.put(reason, listener);
        entryLock.unlock();
    }

    public void createNewPolynomial(PolynomialContext context) {
        try {
            entryLock.lock();
            PolynomialCreator polynomialCreator = polynomialCreators.get(context.getId());
            if (polynomialCreator != null && polynomialCreator.getContext().getReason() != context.getReason() ) {
                logger.debug("Polynomial with id {} is already being created for different reason", context.getId());
                return;
            }

            if (polynomialCreator == null) {
                polynomialCreator = createNewPolynomialCreator(context);
                if (polynomialCreator == null)
                    return;
            }
            polynomialCreator.sendNewPolynomialCreationRequest();
        } finally {
            entryLock.unlock();
        }
    }

    private PolynomialCreator createNewPolynomialCreator(PolynomialContext context) {
        if (context.getId() <= lastPolynomialCreationProcessed) {
            logger.debug("Polynomial creation id {} is old", context.getId());
            return null;
        }

        PolynomialCreator polynomialCreator = new PolynomialCreator(
                context,
                processId,
                shareholderId,
                field,
                rndGenerator,
                cipher,
                commitmentScheme,
                serversCommunication,
                listeners.get(context.getReason())
        );
        polynomialCreators.put(context.getId(), polynomialCreator);
        lastPolynomialCreationProcessed = context.getId();
        return polynomialCreator;
    }

    @Override
    public void messageReceived(InterServerMessageHolder message) {

        while (!pendingMessages.offer(message)){
            logger.debug("Distributed polynomial pending message queue is full");
        }
    }

    @Override
    public void run() {
        while (true) {
            try {
                InterServerMessageHolder message = pendingMessages.take();
                entryLock.lock();
                try (ByteArrayInputStream bis = new ByteArrayInputStream(message.getSerializedMessage());
                     ObjectInput in = new ObjectInputStream(bis)) {
                    switch (message.getType()) {
                        case NEW_POLYNOMIAL:
                            NewPolynomialMessage newPolynomialMessage = new NewPolynomialMessage();
                            newPolynomialMessage.readExternal(in);
                            processNewPolynomialMessage(newPolynomialMessage);
                            break;
                        case POLYNOMIAL_PROPOSAL:
                            ProposalMessage proposalMessage = new ProposalMessage();
                            proposalMessage.readExternal(in);
                            processProposal(message.getSerializedMessage(), proposalMessage);
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
                            processVotes(processedVotesMessage, message.getMessageContext().getConsensusId());
                            break;
                    }
                } catch (IOException e) {
                    logger.error("Failed to deserialize polynomial message of type {}", message.getType(), e);
                }
            } catch (InterruptedException e) {
                break;
            } finally {
                entryLock.unlock();
            }
        }
        logger.debug("Exiting Distributed Polynomial");
    }

    private void processNewPolynomialMessage(NewPolynomialMessage message) {
        logger.debug("Received polynomial generation message from {} with id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.debug("There is no active polynomial creation with id {}", message.getId());
            logger.debug("Creating new polynomial creator for id {} and reason {}", message.getId(),
                    message.getContext().getReason());
            polynomialCreator = createNewPolynomialCreator(message.getContext());
            if (polynomialCreator == null)
                return;
        }

        polynomialCreator.processNewPolynomialMessage(message);
    }

    private void processProposal(byte[] serializedMessage, ProposalMessage message) {
        logger.debug("Received proposal from {} for polynomial creation id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }
        polynomialCreator.processProposal(serializedMessage, message);
    }

    private void processProposalSet(ProposalSetMessage message) {
        logger.debug("Received proposal set from {} for polynomial creation id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }
        polynomialCreator.processProposalSet(message);
    }

    private void processVote(VoteMessage message) {
        logger.debug("Received vote from {} for polynomial creation id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }

        boolean terminated = polynomialCreator.processVote(message);
        if (terminated)
            polynomialCreator.sendProcessedVotes();
    }

    private void processVotes(ProcessedVotesMessage message, int consensusId) {
        logger.debug("Received processed votes from {} for polynomial creation id {} in cid {}", message.getSender(),
                message.getId(), consensusId);
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }
        boolean terminated = polynomialCreator.processVotes(message);
        if (terminated) {
            polynomialCreator.deliverResult(consensusId);
            polynomialCreators.remove(message.getId());
        } else {
            polynomialCreator.startViewChange();

        }
    }

    private void sendMissingProposals(MissingProposalRequestMessage message) {
        logger.debug("Received request to send missing proposal from {} with id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }

        polynomialCreator.generateMissingProposalsResponse(message);
    }

    private void processMissingProposals(MissingProposalsMessage message) {
        logger.debug("Received missing proposals from {} with id {}", message.getSender(),
                message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }
        polynomialCreator.processMissingProposals(message);
    }

    public BigInteger getField() {
        return field;
    }
}
