package confidential.polynomial;

import bftsmart.reconfiguration.ServerViewController;
import confidential.Configuration;
import confidential.interServersCommunication.*;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DistributedPolynomial implements Runnable, InterServerMessageListener {
    private final Logger logger = LoggerFactory.getLogger("polynomial_generation");
    private static final byte[] SEED = "confidential".getBytes();

    private final InterServersCommunication serversCommunication;
    private final SecureRandom rndGenerator;
    private final BigInteger field;
    private final ServerConfidentialityScheme confidentialityScheme;
    private final ConcurrentHashMap<Integer, PolynomialCreator> polynomialCreators;
    private final Map<PolynomialCreationReason, PolynomialCreationListener> listeners;//TODO should I change to concurrentMap?
    private final int processId;
    private final BlockingQueue<InterServerMessageHolder> pendingMessages;
    private final Lock entryLock;
    private final ExecutorService jobsProcessor;
    private final ExecutorService proposalSetVerifierExecutor;
    private final BigInteger[][] vandermondeMatrix;

    public DistributedPolynomial(ServerViewController svController, InterServersCommunication serversCommunication,
                                 ServerConfidentialityScheme confidentialityScheme) {
        this.serversCommunication = serversCommunication;
        this.field = confidentialityScheme.getField();
        this.confidentialityScheme = confidentialityScheme;
        this.rndGenerator = new SecureRandom(("confidential" + svController.getStaticConf().getProcessId()).getBytes());
        this.polynomialCreators = new ConcurrentHashMap<>();
        this.processId = svController.getStaticConf().getProcessId();
        this.listeners = new HashMap<>();
        this.pendingMessages = new LinkedBlockingQueue<>();
        entryLock = new ReentrantLock(true);
        serversCommunication.registerListener(this,
                InterServersMessageType.POLYNOMIAL_PROPOSAL_SET
        );
        MessageListener polynomialMessageListener = new MessageListener(CommunicationTag.POLYNOMIAL) {
            @Override
            public void deliverMessage(InternalMessage message) {
                InterServersMessageType type = InterServersMessageType.getType(message.getMessage()[0]);
                byte[] m = Arrays.copyOfRange(message.getMessage(), 1, message.getMessage().length);
                while (!pendingMessages.offer(new InterServerMessageHolder(type, m, null))){
                    logger.debug("Distributed polynomial pending message queue is full");
                }
            }
        };
        polynomialMessageListener.start();
        boolean isRegistered = serversCommunication.registerListener(polynomialMessageListener);
        if (!isRegistered)
            throw new IllegalStateException("Could not register polynomial message listener");
        int rows = svController.getCurrentViewF() + 1;// svController.getCurrentViewN() - svController.getCurrentViewF();
        int columns = svController.getCurrentViewF() + 1;//svController.getCurrentViewN();
        this.vandermondeMatrix = new BigInteger[rows][columns];
        BigInteger[] matrixInitValues = Configuration.getInstance().getVandermondeMatrixInitializationValues();


        //TODO invert the matrix before using it
        for (int r = 0; r < rows; r++) {
            BigInteger exponent = BigInteger.valueOf(r);
            for (int c = 0; c < columns; c++) {
                vandermondeMatrix[r][c] = matrixInitValues[c].modPow(exponent, field);
            }
        }

        jobsProcessor = Executors.newFixedThreadPool(Configuration.getInstance().getShareProcessingThreads());
        proposalSetVerifierExecutor = Executors.newFixedThreadPool(Configuration.getInstance()
                .getShareProcessingThreads());
    }

    public int getProcessId() {
        return processId;
    }

    public void submitJob(Runnable job) {
        jobsProcessor.execute(job);
    }

    public void submitProposalVerificationJob(Runnable job) {
        proposalSetVerifierExecutor.execute(job);
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

    public BigInteger[][] getVandermondeMatrix() {
        return vandermondeMatrix;
    }

    private PolynomialCreator createNewPolynomialCreator(PolynomialCreationContext context) {
        PolynomialCreator polynomialCreator = PolynomialCreatorFactory.getInstance().getNewCreatorFor(
                context,
                processId,
                rndGenerator,
                confidentialityScheme,
                serversCommunication,
                listeners.get(context.getReason()),
                this
        );

        if (polynomialCreator == null)
            return null;

        polynomialCreators.put(context.getId(), polynomialCreator);
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
        ExecutorService executorService = Executors.newFixedThreadPool(
                Configuration.getInstance().getShareProcessingThreads());
        while (true) {
            try {
                InterServerMessageHolder message = pendingMessages.take();
                entryLock.lock();
                PolynomialMessage polynomialMessage;
                try (ByteArrayInputStream bis = new ByteArrayInputStream(message.getSerializedMessage());
                     ObjectInput in = new ObjectInputStream(bis)) {
                    switch (message.getType()) {
                        case NEW_POLYNOMIAL:
                            polynomialMessage = new NewPolynomialMessage();
                            break;
                        case POLYNOMIAL_PROPOSAL:
                            polynomialMessage = new ProposalMessage();
                            break;
                        case POLYNOMIAL_PROPOSAL_SET:
                            polynomialMessage = new ProposalSetMessage();
                            break;
                        case POLYNOMIAL_REQUEST_MISSING_PROPOSALS:
                            polynomialMessage = new MissingProposalRequestMessage();
                            break;
                        case POLYNOMIAL_MISSING_PROPOSALS:
                            polynomialMessage = new MissingProposalsMessage();
                            break;
                        default:
                            logger.warn("Unknown polynomial message type {}", message.getType());
                            continue;
                    }
                    if (message.getType() == InterServersMessageType.POLYNOMIAL_PROPOSAL) {
                        polynomialMessage = confidentialityScheme.deserializeProposalMessage(in);
                    } else if (message.getType() == InterServersMessageType.POLYNOMIAL_MISSING_PROPOSALS) {
                        polynomialMessage = confidentialityScheme.deserializeMissingProposalMessage(in);
                    } else {
                        polynomialMessage.readExternal(in);
                    }
                    PolynomialCreator polynomialCreator = polynomialCreators.get(polynomialMessage.getId());
                    if (polynomialCreator == null && polynomialMessage instanceof NewPolynomialMessage) {
                        NewPolynomialMessage newPolynomialMessage = (NewPolynomialMessage) polynomialMessage;
                        logger.debug("There is no active polynomial creation with id {}", newPolynomialMessage.getId());
                        logger.debug("Creating new polynomial creator for id {} and reason {}", newPolynomialMessage.getId(),
                                newPolynomialMessage.getContext().getReason());
                        polynomialCreator = createNewPolynomialCreator(newPolynomialMessage.getContext());
                    }
                    if (polynomialCreator == null) {
                        logger.debug("There is no active polynomial creation with id {}", polynomialMessage.getId());
                        continue;
                    }

                    PolynomialCreator finalPolynomialCreator = polynomialCreator;
                    PolynomialMessage finalPolynomialMessage = polynomialMessage;
                    int cid = message.getMessageContext() == null ? -1 : message.getMessageContext().getConsensusId();
                    executorService.execute(() -> finalPolynomialCreator.messageReceived(message.getType(),
                            finalPolynomialMessage, cid));
                } catch (IOException | ClassNotFoundException e) {
                    logger.error("Failed to deserialize polynomial message of type {}", message.getType(), e);
                }
            } catch (InterruptedException e) {
                break;
            } finally {
                entryLock.unlock();
            }
        }
        executorService.shutdown();
        logger.debug("Exiting Distributed Polynomial");
    }

    public boolean isValidProposalSet(ProposalSetMessage message) {
        logger.debug("Received proposal set from {} for polynomial creation id {}", message.getSender(),
                message.getId());
        PolynomialCreator polynomialCreator = polynomialCreators.get(message.getId());
        if (polynomialCreator == null) {
            logger.error("There is no active polynomial creation with id {}", message.getId());
            return false;
        }
        boolean isValid = polynomialCreator.isValidProposalSet(message);
        if (isValid) {
            logger.debug("Accepting proposal set from {} for polynomial creation id {}", message.getSender(),
                    message.getId());
        } else {
            logger.debug("Rejecting proposal set from {} for polynomial creation id {}", message.getSender(),
                    message.getId());
        }
        return isValid;
    }

    public BigInteger getField() {
        return field;
    }

    public void removePolynomialCreator(int id) {
        polynomialCreators.remove(id);
    }
}
