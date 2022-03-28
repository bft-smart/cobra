package confidential.statemanagement;

import bftsmart.statemanagement.SMMessage;
import bftsmart.tom.util.TOMUtil;
import confidential.polynomial.ProposalMessage;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;

/**
 * @author robin
 */
public class PolynomialAccusation extends SMMessage {
	private ProposalMessage[][] invalidProposals;
	private BigInteger[][][] invalidPoints;
	private int accuser;
	private PolynomialRecovery polynomialRecoveryRequest;

	public PolynomialAccusation() {
	}

	public PolynomialAccusation(int sender, int type, ProposalMessage[][] invalidProposals,
								   BigInteger[][][] invalidPoints, int accuser) {
		this(sender, type, invalidProposals, invalidPoints, accuser, null);
	}

	public PolynomialAccusation(int sender, int type, ProposalMessage[][] invalidProposals,
								BigInteger[][][] invalidPoints, int accuser, PolynomialRecovery polynomialRecoveryRequest) {
		super(sender, -1, type, null, null, -1, -1);
		this.invalidProposals = invalidProposals;
		this.invalidPoints = invalidPoints;
		this.accuser = accuser;
		this.polynomialRecoveryRequest = polynomialRecoveryRequest;
	}

	public BigInteger[][][] getInvalidPoints() {
		return invalidPoints;
	}

	public ProposalMessage[][] getInvalidProposals() {
		return invalidProposals;
	}

	public int getAccuser() {
		return accuser;
	}

	public PolynomialRecovery getPolynomialRecoveryRequest() {
		return polynomialRecoveryRequest;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(invalidProposals == null ? -1 : invalidProposals.length);
		if (invalidProposals != null) {
			for (ProposalMessage[] invalidProposal : invalidProposals) {
				out.writeInt(invalidProposal == null ? -1 : invalidProposal.length);
				if (invalidProposal != null) {
					for (ProposalMessage proposalMessage : invalidProposal) {
						proposalMessage.writeExternal(out);
					}
				}
			}
		}
		out.writeInt(invalidPoints == null ? -1 : invalidPoints.length);
		if (invalidPoints != null) {
			for (BigInteger[][] invalidPoint : invalidPoints) {
				out.writeInt(invalidPoint == null ? -1 : invalidPoint.length);
				if (invalidPoint != null) {
					for (BigInteger[] bigIntegers : invalidPoint) {
						out.writeInt(bigIntegers == null ? -1 : bigIntegers.length);
						if (bigIntegers != null) {
							for (BigInteger bigInteger : bigIntegers) {
								out.writeInt(bigInteger.toByteArray().length);
								out.write(bigInteger.toByteArray());
							}
						}
					}
				}
			}
		}
		out.writeInt(accuser);
		out.writeBoolean(polynomialRecoveryRequest != null);
		if (polynomialRecoveryRequest != null)
			polynomialRecoveryRequest.writeExternal(out);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		super.readExternal(in);
		int size = in.readInt();
		if (size > -1) {
			invalidProposals = new ProposalMessage[size][];
			for (int i = 0; i < size; i++) {
				int size2 = in.readInt();
				if (size2 > -1) {
					invalidProposals[i] = new ProposalMessage[size2];
					for (int j = 0; j < size2; j++) {
						ProposalMessage proposalMessage = new ProposalMessage();
						proposalMessage.readExternal(in);
						invalidProposals[i][j] = proposalMessage;
					}
				}
			}
		}

		size = in.readInt();
		if (size > -1) {
			invalidPoints = new BigInteger[size][][];
			for (int i = 0; i < size; i++) {
				int size2 = in.readInt();
				if (size2 > -1) {
					invalidPoints[i] = new BigInteger[size2][];
					for (int j = 0; j < size2; j++) {
						int size3 = in.readInt();
						if (size3 > -1) {
							invalidPoints[i][j] = new BigInteger[size3];
							for (int k = 0; k < size3; k++) {
								byte[] b = new byte[in.readInt()];
								in.readFully(b);
								invalidPoints[i][j][k] = new BigInteger(b);
							}
						}
					}
				}
			}
		}
		accuser = in.readInt();
		if (in.readBoolean()) {
			polynomialRecoveryRequest = new PolynomialRecovery();
			polynomialRecoveryRequest.readExternal(in);
		}
	}
}
