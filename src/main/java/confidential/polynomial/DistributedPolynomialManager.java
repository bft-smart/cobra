package confidential.polynomial;

import confidential.polynomial.creator.ViewStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.Arrays;
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
    private final ConcurrentMap<Integer, ResharingPolynomialContext> resharingPolynomialContexts;
    private final ConcurrentMap<Integer, RecoveryPolynomialContext> recoveryPolynomialContexts;
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
        this.lock = new ReentrantLock(true);
        this.processId = distributedPolynomial.getProcessId();
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RECOVERY);
        distributedPolynomial.registerCreationListener(this, PolynomialCreationReason.RESHARING);
    }

    public int createRecoveryPolynomialsFor(int server, BigInteger shareholderId, int f, int[] members,
                                            int nPolynomials) {
        lock.lock();
        int internalId = internalSequenceNumber;
        PolynomialContext context = new PolynomialContext(
                f,
                shareholderId,
                BigInteger.ZERO,
                members
        );
        logger.info("Starting creation of {} polynomial(s) with initial id {} to recover {} (view: {})", nPolynomials,
                internalId, server, Arrays.toString(members));
        int nExecutions = (int)Math.ceil((double) nPolynomials / (f + 1));
        logger.info("Executing recovery polynomial generation protocol {} times to generate {} polynomial(s)",
                nExecutions, nPolynomials);

        for (int i = 0; i < nExecutions; i++) {
            int id = internalSequenceNumber++;
            int leader = members[id % members.length];
            if (leader == server || leader == 1 || leader == 3) {//TODO for adversarial attack
                int k = 1;
                do {
                    leader = members[(id + k) % members.length];
                    k++;
                } while (leader == server || leader == 1 || leader == 3);
            }
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
        logger.info("Starting creation of {} polynomial(s) with initial id {} for resharing", nPolynomials,
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

    public void setSequenceNumber(int seqNumber) {
        internalSequenceNumber = seqNumber;
    }

    public int getSequenceNumber() {
        return internalSequenceNumber;
    }

    @Override
    public void onPolynomialCreationSuccess(PolynomialCreationContext context, int consensusId,
                                            VerifiableShare[][] points) {
        lock.lock();

        logger.debug("Created new {} polynomial(s) with id {} for {}", points[0].length, context.getId(), context.getReason());
        if (context.getReason() == PolynomialCreationReason.RESHARING) {
            handleResharingPolynomial(context, points, consensusId);
        } else if (context.getReason() == PolynomialCreationReason.RECOVERY) {
            handleRecoveryPolynomial(context, points, consensusId);
        } else {
            logger.warn("Unknown polynomial creation reason {} in creation {}", context.getReason(), context.getId());
        }
        lock.unlock();
    }

    @Override
    public synchronized void onPolynomialCreationFailure(PolynomialCreationContext context, int consensusId,
                                                         ProposalMessage[] invalidProposals, BigInteger[][] invalidPoints) {
        lock.lock();
        if (context.getReason() == PolynomialCreationReason.RESHARING) {
            handleInvalidResharingPolynomial(context, invalidProposals, invalidPoints, consensusId);
        } else if (context.getReason() == PolynomialCreationReason.RECOVERY){
            handleInvalidRecoveryPolynomial(context, invalidProposals, invalidPoints, consensusId);
        } else {
            logger.warn("Unknown polynomial creation reason {} in creation {}", context.getReason(), context.getId());
        }
        lock.unlock();
    }

    private void handleResharingPolynomial(PolynomialCreationContext context, VerifiableShare[][] points, int cid) {
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
        polynomialContext.updateCID(cid);
        internalSequenceNumber = Math.max(internalSequenceNumber, context.getId() + 1);
        if (polynomialContext.currentSize == polynomialContext.getNPolynomials()) {
            polynomialContext.endTime();
            if (polynomialContext.containsInvalidPolynomials()) {
                resharingListener.onResharingPolynomialsFailure(polynomialContext);
            } else {
                double delta = polynomialContext.getTime() / 1_000_000.0;
                logger.info("Took {} ms to create {} polynomial(s) for resharing", delta, polynomialContext.getNPolynomials());
                resharingListener.onResharingPolynomialsCreation(polynomialContext);
            }
        }
    }

    private void handleRecoveryPolynomial(PolynomialCreationContext context, VerifiableShare[][] points, int cid) {
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
        polynomialContext.updateCID(cid);
        internalSequenceNumber = Math.max(internalSequenceNumber, context.getId() + 1);
        if (polynomialContext.currentSize >= polynomialContext.getNPolynomials()) {
            polynomialContext.endTime();
            if (polynomialContext.containsInvalidPolynomials()) {
                recoveryListener.onRecoveryPolynomialsFailure(polynomialContext);
            } else {
                double delta = polynomialContext.getTime() / 1_000_000.0;
                logger.info("Took {} ms to create {} polynomial(s) for recovery", delta,
                        polynomialContext.getNPolynomials());
                recoveryListener.onRecoveryPolynomialsCreation(polynomialContext);
            }
        }
    }

    private void handleInvalidResharingPolynomial(PolynomialCreationContext context,
                                                  ProposalMessage[] invalidProposals, BigInteger[][] invalidPoints,
                                                  int cid) {
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
        polynomialContext.updateCID(cid);
        InvalidPolynomialContext invalidPolynomialContext = new InvalidPolynomialContext(invalidProposals, invalidPoints, 1);
        polynomialContext.addInvalidPolynomialProposals(context.getId(), invalidPolynomialContext);
        internalSequenceNumber = Math.max(internalSequenceNumber, context.getId() + 1);
        if (polynomialContext.currentSize == polynomialContext.getNPolynomials()) {
            resharingListener.onResharingPolynomialsFailure(polynomialContext);
        }
    }

    private void handleInvalidRecoveryPolynomial(PolynomialCreationContext context,
                                                  ProposalMessage[] invalidProposals, BigInteger[][] invalidPoints,
                                                 int cid) {
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
        polynomialContext.updateCID(cid);
        InvalidPolynomialContext invalidPolynomialContext = new InvalidPolynomialContext(invalidProposals, invalidPoints,
                polynomialContext.getF() + 1);
        polynomialContext.addInvalidPolynomialProposals(context.getId(), invalidPolynomialContext);
        internalSequenceNumber = Math.max(internalSequenceNumber, context.getId() + 1);
        if (polynomialContext.currentSize >= polynomialContext.getNPolynomials()) {
            recoveryListener.onRecoveryPolynomialsFailure(polynomialContext);
        }
    }

    private boolean isInView(int member, int[] view) {
        for (int i : view) {
            if (i == member)
                return true;
        }
        return false;
    }
}
