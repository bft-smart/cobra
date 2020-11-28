package confidential.polynomial.creator;

import confidential.interServersCommunication.InterServersCommunication;
import confidential.polynomial.*;
import confidential.server.ServerConfidentialityScheme;
import vss.commitment.Commitment;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

public class ResharingPolynomialCreator extends PolynomialCreator {
    private final ViewStatus viewStatus;

    ResharingPolynomialCreator(PolynomialCreationContext creationContext, int processId, SecureRandom rndGenerator, ServerConfidentialityScheme confidentialityScheme, InterServersCommunication serversCommunication, PolynomialCreationListener creationListener) {
        super(creationContext, processId, rndGenerator, confidentialityScheme, serversCommunication, creationListener,
                creationContext.getContexts()[0].getMembers().length, creationContext.getContexts()[0].getF());
        if (creationContext == null)
            viewStatus = ViewStatus.IN_NEW;
        else {
            boolean inOldView = isInView(processId, creationContext.getContexts()[0].getMembers());
            boolean inNewView = isInView(processId, creationContext.getContexts()[1].getMembers());
            if (inOldView && inNewView)
                viewStatus = ViewStatus.IN_BOTH;
            else
                viewStatus = ViewStatus.IN_OLD;
        }
    }

    @Override
    int[] getMembers(boolean proposalMembers) {
        return proposalMembers ? creationContext.getContexts()[0].getMembers() : allMembers;
    }

    @Override
    ProposalMessage computeProposalMessage() {
        PolynomialContext qOldContext = creationContext.getContexts()[0];
        PolynomialContext qNewContext = creationContext.getContexts()[1];
        BigInteger q = getRandomNumber();

        //generating polynomials
        Polynomial qOld = new Polynomial(field, qOldContext.getF(), q, rndGenerator);
        Polynomial qNew = new Polynomial(field, qNewContext.getF(), q, rndGenerator);

        //generating commitments (BigInteger.Zero to create witness for (0,q) in Kate et al. scheme)
        Commitment qOldCommitment = commitmentScheme.generateCommitments(qOld, BigInteger.ZERO);
        Commitment qNewCommitment = commitmentScheme.generateCommitments(qNew, BigInteger.ZERO);

        //generating shares
        Map<Integer, byte[]> qOldPoints = computeShares(qOld, qOldContext.getMembers());
        Map<Integer, byte[]> qNewPoints = computeShares(qNew, qNewContext.getMembers());

        Proposal forOldView = new Proposal(qOldPoints, qOldCommitment);
        Proposal forNewView = new Proposal(qNewPoints, qNewCommitment);

        return new ProposalMessage(
                creationContext.getId(),
                processId,
                forOldView,
                forNewView
        );
    }

    @Override
    boolean validateProposal(ProposalMessage proposalMessage) {
        Proposal oldViewProposal = proposalMessage.getProposals()[0];
        Proposal newViewProposal = proposalMessage.getProposals()[1];
        int proposalSender = proposalMessage.getSender();

        BigInteger[] decryptedProposalPoints = null;
        Share oldViewShare, newViewShare;

        switch (viewStatus) {
            case IN_OLD:
                oldViewShare = getDecryptedShare(proposalSender, oldViewProposal);
                if (oldViewShare == null)
                    return false;
                if (isValidShare(oldViewProposal.getCommitments(), oldViewShare)
                        && doesEncodeSameSecret(oldViewProposal, newViewProposal)) {
                    validProposals.add(proposalSender);
                    logger.debug("Proposal from {} is valid", proposalSender);
                } else {
                    invalidProposals.add(proposalSender);
                    logger.warn("Proposal from {} is invalid", proposalSender);
                    return false;
                }
                decryptedProposalPoints = new BigInteger[1];
                decryptedProposalPoints[0] = oldViewShare.getShare();
                break;
            case IN_NEW:
                newViewShare = getDecryptedShare(proposalSender, newViewProposal);
                if (newViewShare == null)
                    return false;
                if (isValidShare(newViewProposal.getCommitments(), newViewShare)
                        && doesEncodeSameSecret(oldViewProposal, newViewProposal)) {
                    validProposals.add(proposalSender);
                    logger.debug("Proposal from {} is valid", proposalSender);
                } else {
                    invalidProposals.add(proposalSender);
                    logger.warn("Proposal from {} is invalid", proposalSender);
                    return false;
                }
                decryptedProposalPoints = new BigInteger[1];
                decryptedProposalPoints[0] = newViewShare.getShare();
                break;
            case IN_BOTH:
                oldViewShare = getDecryptedShare(proposalSender, oldViewProposal);
                if (oldViewShare == null)
                    return false;
                newViewShare = getDecryptedShare(proposalSender, newViewProposal);
                if (newViewShare == null)
                    return false;
                if (isValidShare(oldViewProposal.getCommitments(), oldViewShare)
                        && isValidShare(newViewProposal.getCommitments(), newViewShare)
                        && doesEncodeSameSecret(oldViewProposal, newViewProposal)) {
                    validProposals.add(proposalSender);
                    logger.debug("Proposal from {} is valid", proposalSender);
                } else {
                    invalidProposals.add(proposalSender);
                    logger.warn("Proposal from {} is invalid", proposalSender);
                    return false;
                }
                decryptedProposalPoints = new BigInteger[2];
                decryptedProposalPoints[0] = oldViewShare.getShare();
                decryptedProposalPoints[1] = newViewShare.getShare();
                break;
        }
        decryptedPoints.put(proposalSender, decryptedProposalPoints);
        return true;
    }

    private boolean doesEncodeSameSecret(Proposal... proposals) {
        Commitment[] commitments = new Commitment[proposals.length];
        for (int i = 0; i < proposals.length; i++) {
            commitments[i] = proposals[i].getCommitments();
        }
        return commitmentScheme.checkValidityOfPolynomialsProperty(BigInteger.ZERO, commitments);
    }

    private Share getDecryptedShare(int proposalSender, Proposal proposal) {
        byte[] encryptedPoint = proposal.getPoints().get(processId);
        byte[] decryptedPoint = confidentialityScheme.decryptData(processId, encryptedPoint);
        if (decryptedPoint == null) {
            logger.error("Failed to decrypt my point on Q from {}", proposalSender);
            return null;
        }
        BigInteger point = new BigInteger(decryptedPoint);
        return new Share(shareholderId, point);
    }

    private boolean isInView(int member, int[] view) {
        for (int i : view) {
            if (i == member)
                return true;
        }
        return false;
    }
}
