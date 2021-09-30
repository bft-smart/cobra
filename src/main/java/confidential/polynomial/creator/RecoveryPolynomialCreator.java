package confidential.polynomial.creator;

import confidential.interServersCommunication.InterServersCommunication;
import confidential.polynomial.*;
import confidential.server.ServerConfidentialityScheme;
import vss.commitment.Commitment;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Can create multiple recovery polynomials with a same n and f.
 */
public class RecoveryPolynomialCreator extends PolynomialCreator {

    RecoveryPolynomialCreator(PolynomialCreationContext creationContext, int processId, SecureRandom rndGenerator, ServerConfidentialityScheme confidentialityScheme, InterServersCommunication serversCommunication, PolynomialCreationListener creationListener, DistributedPolynomial distributedPolynomial) {
        super(creationContext, processId, rndGenerator, confidentialityScheme, serversCommunication, creationListener,
                creationContext.getContexts()[0].getMembers().length, creationContext.getContexts()[0].getF(), distributedPolynomial);
    }

    @Override
    int[] getMembers(boolean proposalMembers) {
        return allMembers;
    }

    @Override
    ProposalMessage computeProposalMessage() {
        Proposal[] proposals = new Proposal[creationContext.getContexts().length];
        CountDownLatch latch = new CountDownLatch(proposals.length);

        for (int i = 0; i < creationContext.getContexts().length; i++) {
            int finalI = i;
            distributedPolynomial.submitJob(() -> {
                PolynomialContext context = creationContext.getContexts()[finalI];
                //generating polynomial
                Polynomial tempPolynomial = new Polynomial(field, context.getF(),
                        BigInteger.ZERO, rndGenerator);
                BigInteger independentTerm = context.getY().subtract(tempPolynomial.evaluateAt(context.getX()));
                BigInteger[] tempCoefficients = tempPolynomial.getCoefficients();
                BigInteger[] coefficients = Arrays.copyOfRange(tempCoefficients,
                        tempCoefficients.length - tempPolynomial.getDegree() - 1, tempCoefficients.length - 1);

                Polynomial polynomial = new Polynomial(field, independentTerm, coefficients);

                //generating commitments
                Commitment commitments = commitmentScheme.generateCommitments(polynomial);

                //generating shares
                Map<Integer, byte[]> points = computeShares(polynomial, context.getMembers());
                proposals[finalI] = new Proposal(points, commitments);
                latch.countDown();
            });
        }

        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        return new ProposalMessage(
                creationContext.getId(),
                processId,
                proposals
        );
    }

    @Override
    boolean validateProposal(ProposalMessage proposalMessage) {
        int proposalSender = proposalMessage.getSender();
        Proposal[] proposals = proposalMessage.getProposals();
        PolynomialContext[] contexts = creationContext.getContexts();
        if (proposals.length != contexts.length) {
            logger.error("Mismatch between number of polynomial contexts ({}) and proposals ({}) sent by {}.",
                    contexts.length, proposals.length, proposalSender);
            return false;
        }
        BigInteger[] decryptedProposalPoints = new BigInteger[proposals.length];
        AtomicBoolean isValid = new AtomicBoolean(true);
        CountDownLatch latch = new CountDownLatch(proposals.length);

        for (int i = 0; i < proposals.length; i++) {
            Proposal proposal = proposals[i];
            PolynomialContext context = contexts[i];
            int finalI = i;
            distributedPolynomial.submitJob(() -> {
                if (!isValid.get()) {
                    latch.countDown();
                    return;
                }
                byte[] encryptedPoint = proposal.getPoints().get(processId);
                byte[] decryptedPoint = confidentialityScheme.decryptData(processId, encryptedPoint);
                if (decryptedPoint == null) {
                    logger.error("Failed to decrypt my point from {}", proposalMessage.getSender());
                    isValid.set(false);
                } else {
                    BigInteger point = new BigInteger(decryptedPoint);
                    Share share = new Share(shareholderId, point);
                    Share propertyShare = new Share(context.getX(), context.getY());
                    decryptedProposalPoints[finalI] = point;
                    Commitment commitment = proposal.getCommitments();
                    if (commitmentScheme.checkValidityWithoutPreComputation(share, commitment)
                            && commitmentScheme.checkValidityWithoutPreComputation(propertyShare, commitment)) {
                        validProposals.add(proposalSender);
                        logger.debug("Proposal from {} is valid", proposalSender);
                    } else {
                        invalidProposals.add(proposalSender);
                        logger.warn("Proposal from {} is invalid", proposalSender);
                        isValid.set(false);
                    }
                }
                latch.countDown();
            });
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        if (!isValid.get())
            return false;
        decryptedPoints.put(proposalSender, decryptedProposalPoints);
        return true;
    }
}
