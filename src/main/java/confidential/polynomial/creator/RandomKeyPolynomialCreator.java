package confidential.polynomial.creator;

import confidential.interServersCommunication.InterServersCommunication;
import confidential.polynomial.*;
import confidential.server.ServerConfidentialityScheme;
import vss.commitment.Commitment;
import vss.facade.SecretSharingException;
import vss.polynomial.Polynomial;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author robin
 */
public class RandomKeyPolynomialCreator extends PolynomialCreator {
	RandomKeyPolynomialCreator(PolynomialCreationContext creationContext, int processId, SecureRandom rndGenerator,
							   ServerConfidentialityScheme confidentialityScheme, InterServersCommunication serversCommunication,
							   PolynomialCreationListener creationListener,
							   DistributedPolynomial distributedPolynomial) {
		super(creationContext, processId, rndGenerator, confidentialityScheme, serversCommunication, creationListener,
				creationContext.getContexts()[0].getMembers().length, creationContext.getContexts()[0].getF(),
				distributedPolynomial);
	}

	@Override
	int[] getMembers(boolean proposalMembers) {
		return allMembers;
	}

	@Override
	ProposalMessage computeProposalMessage() {
		BigInteger field = confidentialityScheme.getEllipticCurveField();
		BigInteger privateKey = getRandomNumber(field);

		Proposal[] proposals = new Proposal[creationContext.getContexts().length];
		CountDownLatch latch = new CountDownLatch(proposals.length);
		for (int i = 0; i < creationContext.getContexts().length; i++) {
			int finalI = i;
			distributedPolynomial.submitJob(() -> {
				PolynomialContext context = creationContext.getContexts()[finalI];
				//generating polynomial
				Polynomial polynomial = new Polynomial(field, context.getF(), privateKey, rndGenerator);

				//generating commitments
				Commitment commitment = confidentialityScheme.generateEllipticCurveCommitment(polynomial);

				//generating shares
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
					decryptedProposalPoints[finalI] = point;
					Commitment commitment = proposal.getCommitments();
					if (confidentialityScheme.checkEllipticCurveCommitment(share, commitment)) {
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

	@Override
	public void deliverResult(int consensusId, ProposalSetMessage proposalSet) {
		BigInteger[][] finalPoint = null;
		Commitment[][] allCommitments = null;
		int i = 0;
		List<ProposalMessage> invalidProposals = new LinkedList<>();
		for (int member : proposalSet.getReceivedNodes()) {
			ProposalMessage proposal = proposals.get(member);
			if (this.invalidProposals.contains(member))
				invalidProposals.add(proposal);
		}

		if (!invalidProposals.isEmpty()) {
			creationListener.onPolynomialCreationFailure(creationContext, invalidProposals, consensusId);
			return;
		}

		for (int member : proposalSet.getReceivedNodes()) {
			BigInteger[] points = decryptedPoints.get(member);
			if (points == null) { //if this replica did not received some proposals
				creationListener.onPolynomialCreationFailure(creationContext, invalidProposals,
						consensusId);
				return;
			}
			if (finalPoint == null) {
				int nPolynomials = points.length;

				finalPoint = new BigInteger[nPolynomials][1];
				for (int j = 0; j < finalPoint.length; j++) {
					finalPoint[j][0] = BigInteger.ZERO;
				}
				allCommitments = new Commitment[nPolynomials][faultsThreshold + 1];
			}
			for (int j = 0; j < finalPoint.length; j++) {

				finalPoint[j][0] = finalPoint[j][0].add(points[j]);
				allCommitments[j][i] = proposals.get(member).getProposals()[j].getCommitments();
			}
			i++;
		}
		if (finalPoint == null) {
			logger.error("Something went wrong while computing final point");
			return;
		}
		VerifiableShare[][] result;
		result = new VerifiableShare[finalPoint.length][1];
		for (int j = 0; j < finalPoint.length; j++) {
			Share share = new Share(shareholderId, finalPoint[j][0]);
			Commitment commitment = null;
			try {
				commitment = confidentialityScheme.sumEllipticCurveCommitments(allCommitments[j]);
			} catch (SecretSharingException e) {
				logger.error("Failed to combine commitments", e);
			}
			result[j][0] =  new VerifiableShare(share, commitment, null);
		}
		creationListener.onPolynomialCreationSuccess(creationContext, consensusId, result);
	}

	protected BigInteger getRandomNumber(BigInteger field) {
		BigInteger rndBig = new BigInteger(field.bitLength() - 1, rndGenerator);
		if (rndBig.compareTo(BigInteger.ZERO) == 0) {
			rndBig = rndBig.add(BigInteger.ONE);
		}

		return rndBig;
	}
}
