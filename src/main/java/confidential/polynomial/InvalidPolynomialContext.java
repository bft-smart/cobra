package confidential.polynomial;

import java.math.BigInteger;

/**
 * @author robin
 */
public class InvalidPolynomialContext {
	private final ProposalMessage[] invalidProposals;
	private final BigInteger[][] invalidPoints;
	private final int nInvalidPolynomials;

	public InvalidPolynomialContext(ProposalMessage[] invalidProposals, BigInteger[][] invalidPoints,
									int nInvalidPolynomials) {
		this.invalidProposals = invalidProposals;
		this.invalidPoints = invalidPoints;
		this.nInvalidPolynomials = nInvalidPolynomials;
	}

	public int getNInvalidPolynomials() {
		return nInvalidPolynomials;
	}

	public ProposalMessage[] getInvalidProposals() {
		return invalidProposals;
	}

	public BigInteger[][] getInvalidPoints() {
		return invalidPoints;
	}
}
