package confidential.polynomial;

import bftsmart.reconfiguration.ServerViewController;
import confidential.interServersCommunication.InterServerMessageHolder;
import confidential.interServersCommunication.InterServerMessageListener;
import confidential.interServersCommunication.InterServersCommunication;
import confidential.interServersCommunication.InterServersMessageType;
import confidential.polynomial.creator.PolynomialCreator;
import confidential.polynomial.creator.PolynomialCreatorFactory;
import confidential.server.ServerConfidentialityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DistributedPolynomial implements InterServerMessageListener, Runnable {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private static final byte[] SEED = "confidential".getBytes();

    private ServerViewController svController;
    private final InterServersCommunication serversCommunication;
    private final SecureRandom rndGenerator;
    private final BigInteger field;
    private final ServerConfidentialityScheme confidentialityScheme;
    private final Map<Integer, PolynomialCreator> polynomialCreators;//TODO should I change to concurrentMap?
    private final Map<PolynomialCreationReason, PolynomialCreationListener> listeners;//TODO should I change to concurrentMap?
    private final int processId;
    private int lastPolynomialCreationProcessed;
    private final BlockingQueue<InterServerMessageHolder> pendingMessages;
    private final Lock entryLock;

    public DistributedPolynomial(ServerViewController svController, InterServersCommunication serversCommunication,
                                 ServerConfidentialityScheme confidentialityScheme) {
        this.svController = svController;
        this.serversCommunication = serversCommunication;
        this.field = confidentialityScheme.getField();
        this.confidentialityScheme = confidentialityScheme;
        this.rndGenerator = new SecureRandom(SEED);
        this.polynomialCreators = new HashMap<>();
        this.processId = svController.getStaticConf().getProcessId();
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

    public void registerCreationListener(PolynomialCreationListener listener, PolynomialCreationReason reason) {
        entryLock.lock();
        listeners.put(reason, listener);
        entryLock.unlock();
    }

    public void createNewPolynomial(PolynomialCreationContext context) {
        try {
            entryLock.lock();
            PolynomialCreator polynomialCreator = polynomialCreators.get(context.getId());
            if (polynomialCreator != null && !polynomialCreator.getCreationContext().getReason().equals(context.getReason())) {
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

    private PolynomialCreator createNewPolynomialCreator(PolynomialCreationContext context) {
        if (context.getId() <= lastPolynomialCreationProcessed) {
            logger.debug("Polynomial creation id {} is old", context.getId());
            return null;
        }

        PolynomialCreator polynomialCreator = PolynomialCreatorFactory.getInstance().getNewCreatorFor(
                context,
                processId,
                rndGenerator,
                confidentialityScheme,
                serversCommunication,
                listeners.get(context.getReason())
        );

        if (polynomialCreator == null)
            return null;

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
                            processProposal(proposalMessage);
                            break;
                        case POLYNOMIAL_PROPOSAL_SET:
                            ProposalSetMessage proposalSetMessage = new ProposalSetMessage();
                            proposalSetMessage.readExternal(in);
                            deliverResult(proposalSetMessage,
                                    message.getMessageContext().getConsensusId());
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
                    }
                } catch (IOException | ClassNotFoundException e) {
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

    private void processProposal(ProposalMessage message) {
        logger.debug("Received proposal from {} for polynomial creation id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }
        polynomialCreator.processProposal(message);
    }

    public boolean isValidProposalSet(ProposalSetMessage message) {
        logger.debug("Received proposal set from {} for polynomial creation id {}", message.getSender(), message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return false;
        }
        return polynomialCreator.isValidProposalSet(message);
    }

    private void deliverResult(ProposalSetMessage message, int cid) {
        logger.debug("Received proposal set from {} for polynomial creation id {} in " +
                "cid {}", message.getSender(), message.getId(), cid);
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return;
        }
        polynomialCreator.deliverResult(cid, message);
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
