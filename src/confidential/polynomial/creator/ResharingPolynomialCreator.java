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
import java.util.concurrent.CountDownLatch;

public class ResharingPolynomialCreator extends PolynomialCreator {
    private final ViewStatus viewStatus;

    ResharingPolynomialCreator(PolynomialCreationContext creationContext, int processId, SecureRandom rndGenerator,
                               ServerConfidentialityScheme confidentialityScheme,
                               InterServersCommunication serversCommunication,
                               PolynomialCreationListener creationListener,
                               DistributedPolynomial distributedPolynomial) {
        super(creationContext, processId, rndGenerator, confidentialityScheme, serversCommunication, creationListener,
                creationContext.getContexts()[0].getMembers().length, creationContext.getContexts()[0].getF(),
                distributedPolynomial);
        boolean inOldView = isInView(processId, creationContext.getContexts()[0].getMembers());
        boolean inNewView = isInView(processId, creationContext.getContexts()[1].getMembers());
        if (inOldView && inNewView)
            viewStatus = ViewStatus.IN_BOTH;
        else if (inOldView)
            viewStatus = ViewStatus.IN_OLD;
        else
            viewStatus = ViewStatus.IN_NEW;
    }

    @Override
    int[] getMembers(boolean proposalMembers) {
        return proposalMembers ? creationContext.getContexts()[0].getMembers() : allMembers;
    }

    @Override
    ProposalMessage computeProposalMessage() {
        BigInteger q = getRandomNumber();
        Proposal[] proposals = new Proposal[2];

        CountDownLatch latch = new CountDownLatch(2);
        for (int i = 0; i < proposals.length; i++) {
            PolynomialContext context = creationContext.getContexts()[i];
            int finalI = i;
            distributedPolynomial.submitJob(() -> {
                Polynomial polynomial = new Polynomial(field, context.getF(), q, rndGenerator);
                Commitment commitment = commitmentScheme.generateCommitments(polynomial, BigInteger.ZERO);
                Map<Integer, byte[]> points = computeShares(polynomial, context.getMembers());
                proposals[finalI] = new Proposal(points, commitment);
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
        Proposal oldViewProposal = proposalMessage.getProposals()[0];
        Proposal newViewProposal = proposalMessage.getProposals()[1];
        int proposalSender = proposalMessage.getSender();

        BigInteger[] decryptedProposalPoints = null;
        Share oldViewShare, newViewShare;
        boolean[] isValid;

        switch (viewStatus) {
            case IN_OLD:
                oldViewShare = getDecryptedShare(proposalSender, oldViewProposal);
                if (oldViewShare == null)
                    return false;
                isValid = new boolean[2];
                isValid[0] = commitmentScheme.checkValidityWithoutPreComputation(oldViewShare,
                        oldViewProposal.getCommitments());
                isValid[1] = doesEncodeSameSecret(oldViewProposal, newViewProposal);

                if (isValid[0] && isValid[1]) {
                    validProposals.add(proposalSender);
                    logger.debug("Proposal from {} is valid for creation {}", proposalSender, proposalMessage.getId());
                } else {
                    invalidProposals.add(proposalSender);
                    logger.warn("Proposal from {} is invalid for creation {}", proposalSender, proposalMessage.getId());
                    return false;
                }
                decryptedProposalPoints = new BigInteger[1];
                decryptedProposalPoints[0] = oldViewShare.getShare();
                break;
            case IN_NEW:
                newViewShare = getDecryptedShare(proposalSender, newViewProposal);
                if (newViewShare == null)
                    return false;
                isValid = new boolean[2];
                isValid[0] = commitmentScheme.checkValidityWithoutPreComputation(newViewShare,
                        newViewProposal.getCommitments());
                isValid[1] = doesEncodeSameSecret(oldViewProposal, newViewProposal);

                if (isValid[0] && isValid[1]) {
                    validProposals.add(proposalSender);
                    logger.debug("Proposal from {} is valid for creation {}", proposalSender, proposalMessage.getId());
                } else {
                    invalidProposals.add(proposalSender);
                    logger.warn("Proposal from {} is invalid for creation {}", proposalSender, proposalMessage.getId());
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
                isValid = new boolean[3];
                isValid[0] = commitmentScheme.checkValidityWithoutPreComputation(oldViewShare,
                        oldViewProposal.getCommitments());
                isValid[1] = commitmentScheme.checkValidityWithoutPreComputation(newViewShare,
                        newViewProposal.getCommitments());
                isValid[2] = doesEncodeSameSecret(oldViewProposal, newViewProposal);

                if (isValid[0] && isValid[1] && isValid[2]) {
                    validProposals.add(proposalSender);
                    logger.debug("Proposal from {} is valid for creation {}", proposalSender, proposalMessage.getId());
                } else {
                    invalidProposals.add(proposalSender);
                    logger.warn("Proposal from {} is invalid for creation {}", proposalSender, proposalMessage.getId());
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
