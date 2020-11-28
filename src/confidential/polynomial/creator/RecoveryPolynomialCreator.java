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

/**
 * Can create multiple recovery polynomials with a same n and f.
 */
public class RecoveryPolynomialCreator extends PolynomialCreator {

    RecoveryPolynomialCreator(PolynomialCreationContext creationContext, int processId, SecureRandom rndGenerator, ServerConfidentialityScheme confidentialityScheme, InterServersCommunication serversCommunication, PolynomialCreationListener creationListener) {
        super(creationContext, processId, rndGenerator, confidentialityScheme, serversCommunication, creationListener,
                creationContext.getContexts()[0].getMembers().length, creationContext.getContexts()[0].getF());
    }

    @Override
    int[] getMembers(boolean proposalMembers) {
        return allMembers;
    }

    @Override
    ProposalMessage computeProposalMessage() {
        Proposal[] proposals = new Proposal[creationContext.getContexts().length];
        for (int i = 0; i < creationContext.getContexts().length; i++) {
            PolynomialContext context = creationContext.getContexts()[i];
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
            proposals[i] = new Proposal(points, commitments);
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
        for (int i = 0; i < proposals.length; i++) {
            Proposal proposal = proposals[i];
            PolynomialContext context = contexts[i];

            byte[] encryptedPoint = proposal.getPoints().get(processId);
            byte[] decryptedPoint = confidentialityScheme.decryptData(processId, encryptedPoint);
            if (decryptedPoint == null) {
                logger.error("Failed to decrypt my point from {}", proposalMessage.getSender());
                return false;
            }
            BigInteger point = new BigInteger(decryptedPoint);
            Share share = new Share(shareholderId, point);
            Share propertyShare = new Share(context.getX(), context.getY());
            decryptedProposalPoints[i] = point;
            if (isValidShare(proposal.getCommitments(), share, propertyShare)) {
                validProposals.add(proposalSender);
                logger.debug("Proposal from {} is valid", proposalSender);
            } else {
                invalidProposals.add(proposalSender);
                logger.warn("Proposal from {} is invalid", proposalSender);
                return false;
            }
        }
        decryptedPoints.put(proposalSender, decryptedProposalPoints);
        return true;
    }
}
