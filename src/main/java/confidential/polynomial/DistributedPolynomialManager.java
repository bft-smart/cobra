package confidential.polynomial;

import confidential.polynomial.creator.ViewStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DistributedPolynomialManager implements PolynomialCreationListener {
    private final Logger logger = LoggerFactory.getLogger("polynomial_generation");
    private int internalSequenceNumber;
    private final DistributedPolynomial distributedPolynomial;
    private final ResharingPolynomialListener resharingListener;
    private final RecoveryPolynomialListener recoveryListener;
    private RandomPolynomialListener randomPolynomialListener;
    private RandomKeyPolynomialListener randomKeyPolynomialListener;
    private final ConcurrentMap<Integer, ResharingPolynomialContext> resharingPolynomialContexts;
    private final ConcurrentMap<Integer, RecoveryPolynomialContext> recoveryPolynomialContexts;
    private final ConcurrentMap<Integer, RandomPolynomialContext> randomPolynomialContexts;
    private final ConcurrentMap<Integer, RandomPolynomialContext> randomKeyPolynomialContexts;
    private final Lock lock;
    private final int processId;

    public DistributedPolynomialManager(DistributedPolynomial distributedPolynomial,
                                        ResharingPolynomialListener resharingListener,
                                        RecoveryPolynomialListener recoveryListener) {
        this.distributedPolynomial = distributedPolynomial;
        this.resharingListener = resharingListener;
        this.recoveryListener = recoveryListener;
        this.resharingPolynomialContexts = new ConcurrentHashMap<>();
        this.recoveryPolynomialContexts = new ConcurrentHashMap<>();
        this.randomPolynomialContexts = new ConcurrentHashMap<>();
        this.randomKeyPolynomialContexts = new ConcurrentHashMap<>();
        this.lock = new ReentrantLock(true);
        this.processId = distributedPolynomial.getProcessId();
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RECOVERY);
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RESHARING);
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RANDOM);
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RANDOM_KEY);
    }

    public void setRandomPolynomialListener(RandomPolynomialListener randomPolynomialListener) {
        this.randomPolynomialListener = randomPolynomialListener;
    }

    public void setRandomKeyPolynomialListener(RandomKeyPolynomialListener randomKeyPolynomialListener) {
        this.randomKeyPolynomialListener = randomKeyPolynomialListener;
    }

    public int createRecoveryPolynomialsFor(BigInteger shareholder, int f, int[] members,
                                            int nPolynomials) {
        lock.lock();
        int internalId = internalSequenceNumber;
        PolynomialContext context = new PolynomialContext(
                f,
                shareholder,
                BigInteger.ZERO,
                members
        );
        logger.info("Starting creation of {} polynomial(s) with id {} to recover {}", nPolynomials,
                internalId, shareholder);
        int nExecutions = (int)Math.ceil((double) nPolynomials / (f + 1));
        logger.info("Executing polynomial generation protocol {} times to generate {} polynomial(s)",
                nExecutions, nPolynomials);
        for (int i = 0; i < nExecutions; i++) {
            int id = internalSequenceNumber++;
            int leader = members[id % members.length];
            PolynomialCreationContext creationContext = new PolynomialCreationContext(
                    id,
                    internalId,
                    nPolynomials,
                    false,
                    true,
                    leader,
                    PolynomialCreationReason.RECOVERY,
                    context
            );
            distributedPolynomial.createNewPolynomial(creationContext);
        }

        RecoveryPolynomialContext recoveryPolynomialContext = new RecoveryPolynomialContext(
                internalId,
                nPolynomials,
                f);
        if (!recoveryPolynomialContexts.containsKey(internalId)) {
            recoveryPolynomialContext.startTime();
            recoveryPolynomialContexts.put(internalId, recoveryPolynomialContext);
        } else {
            logger.warn("There is already an active recovery polynomial creation with internal id {}", internalId);
        }
        lock.unlock();
        return internalId;
    }

    public void createResharingPolynomials(int oldF, int[] oldMembers, int newF, int[] newMembers, int nPolynomials) {
        lock.lock();
        PolynomialContext oldView = new PolynomialContext(
                oldF,
                BigInteger.ZERO,
                null,
                oldMembers
        );
        PolynomialContext newView = new PolynomialContext(
                newF,
                BigInteger.ZERO,
                null,
                newMembers
        );
        int internalId = internalSequenceNumber;
        logger.info("Starting creation of {} polynomial(s) with id {} for resharing", nPolynomials,
                internalId);
        for (int i = 0; i < nPolynomials; i++) {
            int id = internalSequenceNumber++;
            int leader = oldMembers[id % oldMembers.length];
            PolynomialCreationContext creationContext = new PolynomialCreationContext(
                    id,
                    internalId,
                    nPolynomials,
                    false,
                    false,
                    leader,
                    PolynomialCreationReason.RESHARING,
                    oldView,
                    newView
            );
            logger.debug("Starting creation of new polynomial with id {} for resharing", id);
            distributedPolynomial.createNewPolynomial(creationContext);
        }
        ViewStatus viewStatus;
        boolean inOldView = isInView(processId, oldMembers);
        boolean inNewView = isInView(processId, newMembers);
        if (inOldView && inNewView)
            viewStatus = ViewStatus.IN_BOTH;
        else if (inOldView)
            viewStatus = ViewStatus.IN_OLD;
        else
            viewStatus = ViewStatus.IN_NEW;
        ResharingPolynomialContext context = new ResharingPolynomialContext(
                internalId,
                nPolynomials,
                oldF,
                newF,
                oldMembers,
                newMembers,
                viewStatus
        );

        if (!resharingPolynomialContexts.containsKey(internalId)) {
            context.startTime();
            resharingPolynomialContexts.put(internalId, context);
        } else
            logger.warn("There is already an active resharing polynomial creation with internal id {}", internalId);
        lock.unlock();
    }

    public int createRandomPolynomial(int f, int[] members) {
        if (randomPolynomialListener == null)
            throw new IllegalStateException("RandomPolynomialListener is not set in DistributedPolynomialManager");
        lock.lock();
        int internalId = internalSequenceNumber++;
        PolynomialContext context = new PolynomialContext(
                f,
                BigInteger.ZERO,
                null,
                members
        );
        logger.info("Starting creation of a polynomial with id {}", internalId);
        int leader = members[internalId % members.length];
        PolynomialCreationContext creationContext = new PolynomialCreationContext(
                    internalId,
                    internalId,
                    1,
                    false,
                    false,
                    leader,
                    PolynomialCreationReason.RANDOM,
                    context
            );
            distributedPolynomial.createNewPolynomial(creationContext);

        RandomPolynomialContext randomPolynomialContext = new RandomPolynomialContext(
                internalId,
                1,
                f);
        if (!randomPolynomialContexts.containsKey(internalId)) {
            randomPolynomialContext.startTime();
            randomPolynomialContexts.put(internalId, randomPolynomialContext);
        } else {
            logger.warn("There is already an active random polynomial creation with internal id {}", internalId);
        }
        lock.unlock();
        return internalId;
    }

    public int createRandomKeyPolynomial(int f, int[] members) {
        if (randomKeyPolynomialListener == null)
            throw new IllegalStateException("RandomKeyPolynomialListener is not set in DistributedPolynomialManager");
        lock.lock();
        int internalId = internalSequenceNumber++;
        PolynomialContext context = new PolynomialContext(
                f,
                BigInteger.ZERO,
                null,
                members
        );
        logger.info("Starting creation of a polynomial with id {}", internalId);
        int leader = members[internalId % members.length];
        PolynomialCreationContext creationContext = new PolynomialCreationContext(
                internalId,
                internalId,
                1,
                false,
                false,
                leader,
                PolynomialCreationReason.RANDOM_KEY,
                context
        );
        distributedPolynomial.createNewPolynomial(creationContext);

        RandomPolynomialContext randomPolynomialContext = new RandomPolynomialContext(
                internalId,
                1,
                f);
        if (!randomKeyPolynomialContexts.containsKey(internalId)) {
            randomPolynomialContext.startTime();
            randomKeyPolynomialContexts.put(internalId, randomPolynomialContext);
        } else {
            logger.warn("There is already an active random key polynomial creation with internal id {}", internalId);
        }
        lock.unlock();
        return internalId;
    }

    public void setSequenceNumber(int seqNumber) {
        internalSequenceNumber = seqNumber;
    }

    public int getSequenceNumber() {
        return internalSequenceNumber;
    }

    //TODO check if all servers receive their points in same order
    @Override
    public void onPolynomialCreationSuccess(PolynomialCreationContext context, int consensusId,
                                            VerifiableShare[][] points) {
        lock.lock();
        logger.debug("Created new {} polynomial(s) with id {}", points[0].length, context.getId());

        if (context.getReason() == PolynomialCreationReason.RESHARING) {
            handleResharingPolynomial(context, consensusId, points);
        } else if (context.getReason() == PolynomialCreationReason.RECOVERY) {
            handleRecoveryPolynomial(context, consensusId, points);
        } else if (context.getReason() == PolynomialCreationReason.RANDOM) {
            handleRandomPolynomial(context, consensusId, points);
        } else if (context.getReason() == PolynomialCreationReason.RANDOM_KEY)
            handleRandomKeyPolynomial(context, consensusId, points);
        lock.unlock();
    }

    private void handleRandomKeyPolynomial(PolynomialCreationContext context, int consensusId, VerifiableShare[][] points) {
        RandomPolynomialContext polynomialContext = randomKeyPolynomialContexts.remove(context.getInternalId());
        if (polynomialContext == null) {
            logger.debug("There is no random polynomial context. Creating one");
            polynomialContext = new RandomPolynomialContext(
                    context.getInternalId(),
                    context.getNPolynomials(),
                    context.getContexts()[0].getF()
            );
        }
        polynomialContext.endTime();
        polynomialContext.setPoint(points[0][0]);
        polynomialContext.setCID(consensusId);
        randomKeyPolynomialListener.onRandomKeyPolynomialsCreation(polynomialContext);
    }

    private void handleRandomPolynomial(PolynomialCreationContext context, int consensusId, VerifiableShare[][] points) {
        RandomPolynomialContext polynomialContext = randomPolynomialContexts.remove(context.getInternalId());
        if (polynomialContext == null) {
            logger.debug("There is no random polynomial context. Creating one");
            polynomialContext = new RandomPolynomialContext(
                    context.getInternalId(),
                    context.getNPolynomials(),
                    context.getContexts()[0].getF()
            );
        }
        polynomialContext.endTime();
        polynomialContext.setPoint(points[0][0]);
        polynomialContext.setCID(consensusId);
        randomPolynomialListener.onRandomPolynomialsCreation(polynomialContext);
    }

    private void handleRecoveryPolynomial(PolynomialCreationContext context, int consensusId, VerifiableShare[][] points) {
        RecoveryPolynomialContext polynomialContext = recoveryPolynomialContexts.get(context.getInternalId());
        if (polynomialContext == null) {
            logger.debug("There is no recovery polynomial context. Creating one");
            polynomialContext = new RecoveryPolynomialContext(
                    context.getInternalId(),
                    context.getNPolynomials(),
                    context.getContexts()[0].getF()
            );
            recoveryPolynomialContexts.put(context.getInternalId(), polynomialContext);
        }
        for (VerifiableShare[] point : points) {
            polynomialContext.addPolynomial(context.getId(), point);
        }

        polynomialContext.setCID(consensusId);
        if (polynomialContext.currentIndex % 10000 == 0
                && polynomialContext.currentIndex < polynomialContext.getNPolynomials())
            logger.info("{} polynomial(s) created", polynomialContext.currentIndex);

        if (polynomialContext.currentIndex >= polynomialContext.getNPolynomials()) {
            polynomialContext.endTime();
            double delta = polynomialContext.getTime() / 1_000_000.0;
            logger.info("Took {} ms to create {} polynomial(s) for recovery", delta,
                    polynomialContext.getNPolynomials());
            recoveryListener.onRecoveryPolynomialsCreation(polynomialContext);
        }
    }

    private void handleResharingPolynomial(PolynomialCreationContext context, int consensusId, VerifiableShare[][] points) {
        ResharingPolynomialContext polynomialContext = resharingPolynomialContexts.get(context.getInternalId());
        if (polynomialContext == null) {
            logger.debug("There is no resharing polynomial context. Creating one");
            PolynomialContext oldContext = context.getContexts()[0];
            PolynomialContext newContext = context.getContexts()[1];
            ViewStatus viewStatus;
            boolean inOldView = isInView(processId, oldContext.getMembers());
            boolean inNewView = isInView(processId, newContext.getMembers());
            if (inOldView && inNewView)
                viewStatus = ViewStatus.IN_BOTH;
            else if (inOldView)
                viewStatus = ViewStatus.IN_OLD;
            else
                viewStatus = ViewStatus.IN_NEW;
            polynomialContext = new ResharingPolynomialContext(
                    context.getInternalId(),
                    context.getNPolynomials(),
                    oldContext.getF(),
                    newContext.getF(),
                    oldContext.getMembers(),
                    newContext.getMembers(),
                    viewStatus
            );
            resharingPolynomialContexts.put(context.getInternalId(), polynomialContext);
        }
        int size = points[0].length;
        if (points.length == 1) {
            for (int i = 0; i < size; i++) {
                polynomialContext.addPolynomial(context.getId(), points[0][i]);
            }
        } else {
            for (int i = 0; i < size; i++) {
                polynomialContext.addPolynomial(context.getId(), points[0][i], points[1][i]);
            }
        }
        polynomialContext.setCID(consensusId);
        if (polynomialContext.currentIndex % 5000 == 0 && polynomialContext.currentIndex != polynomialContext.getNPolynomials())
            logger.info("{} polynomial(s) created", polynomialContext.currentIndex);

        if (polynomialContext.currentIndex == polynomialContext.getNPolynomials()) {
            polynomialContext.endTime();
            double delta = polynomialContext.getTime() / 1_000_000.0;
            logger.info("Took {} ms to create {} polynomial(s) for resharing", delta, polynomialContext.getNPolynomials());
            resharingListener.onResharingPolynomialsCreation(polynomialContext);
        }
    }

    @Override
    public synchronized void onPolynomialCreationFailure(PolynomialCreationContext context,
                                                         List<ProposalMessage> invalidProposals, int consensusId) {
        logger.error("I received an invalid point");
        System.exit(-1);
    }

    private boolean isInView(int member, int[] view) {
        for (int i : view) {
            if (i == member)
                return true;
        }
        return false;
    }
}
