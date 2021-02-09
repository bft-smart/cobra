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
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private int sequenceNumber;
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

    public int createRecoveryPolynomialsFor(BigInteger shareholder, int f, int[] members,
                                                         int nPolynomials) {
        lock.lock();
        int internalId = internalSequenceNumber++;
        PolynomialContext context = new PolynomialContext(
                f,
                shareholder,
                BigInteger.ZERO,
                members
        );
        logger.info("Starting creation of {} polynomial(s) with id {} to recover {}", nPolynomials,
                internalId, shareholder);
        int nExecutions = (int)((double) nPolynomials / (f + 1) + 0.5);
        logger.info("Executing polynomial generation protocol {} times to generate {} polynomial(s)",
                nExecutions, nPolynomials);
        for (int i = 0; i < nExecutions; i++) {
            int id = sequenceNumber++;
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
        recoveryPolynomialContexts.put(internalId, recoveryPolynomialContext);
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
        int internalId = internalSequenceNumber++;
        logger.info("Starting creation of {} polynomial(s) with id {} for resharing", nPolynomials,
                internalId);
        for (int i = 0; i < nPolynomials; i++) {
            int id = sequenceNumber++;
            int leader = 0;//oldMembers[id % oldMembers.length];
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
        context.startTime();
        resharingPolynomialContexts.put(internalId, context);
        lock.unlock();
    }

    public void setSequenceNumber(int seqNumber) {
        internalSequenceNumber = seqNumber;
    }

    public int getSequenceNumber() {
        return internalSequenceNumber;
    }

    @Override
    public synchronized void onPolynomialCreationSuccess(PolynomialCreationContext context, int consensusId,
                                            VerifiableShare[][] points) {
        if (context.getReason() == PolynomialCreationReason.RESHARING) {
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
            }
            int size = points[0].length;
            if (points.length == 1) {
                for (int i = 0; i < size; i++) {
                    polynomialContext.addPolynomial(points[0][i]);
                }
            } else {
                for (int i = 0; i < size; i++) {
                    polynomialContext.addPolynomial(points[0][i], points[1][i]);
                }
            }
            if (polynomialContext.currentIndex % 25 == 0 && polynomialContext.currentIndex != polynomialContext.getNPolynomials())
                logger.info("{} polynomial(s) created", polynomialContext.currentIndex);

            if (polynomialContext.currentIndex == polynomialContext.getNPolynomials()) {
                polynomialContext.endTime();
                double delta = polynomialContext.getTime() / 1_000_000.0;
                logger.info("Took {} ms to create {} polynomial(s) for resharing", delta, polynomialContext.getNPolynomials());
                resharingListener.onResharingPolynomialsCreation(polynomialContext, consensusId);
            }
        } else if (context.getReason() == PolynomialCreationReason.RECOVERY) {
            RecoveryPolynomialContext polynomialContext = recoveryPolynomialContexts.get(context.getInternalId());
            if (polynomialContext == null) {
                logger.debug("There is no recovery polynomial context. Creating one");
                polynomialContext = new RecoveryPolynomialContext(
                        context.getInternalId(),
                        context.getNPolynomials(),
                        context.getContexts()[0].getF()
                );
            }
            for (VerifiableShare[] point : points) {
                for (VerifiableShare share : point) {
                    polynomialContext.addPolynomial(share);
                }
            }
            if (polynomialContext.currentIndex % 25 == 0 && polynomialContext.currentIndex < polynomialContext.getNPolynomials())
                logger.info("{} polynomial(s) created", polynomialContext.currentIndex);

            if (polynomialContext.currentIndex >= polynomialContext.getNPolynomials()) {
                polynomialContext.endTime();
                double delta = polynomialContext.getTime() / 1_000_000.0;
                logger.info("Took {} ms to create {} polynomial(s) for recovery", delta, polynomialContext.getNPolynomials());
                recoveryListener.onRecoveryPolynomialsCreation(polynomialContext, consensusId);
            }
        }
    }

    @Override
    public synchronized void onPolynomialCreationFailure(PolynomialCreationContext context, List<ProposalMessage> invalidProposals,
                                            int consensusId) {
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
