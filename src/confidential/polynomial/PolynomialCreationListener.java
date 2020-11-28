package confidential.polynomial;

import vss.secretsharing.VerifiableShare;

import java.util.List;

public interface PolynomialCreationListener {
    void onPolynomialCreationSuccess(PolynomialCreationContext context, int consensusId,
                                     VerifiableShare... points);
    void onPolynomialCreationFailure(PolynomialCreationContext context,
                                     List<ProposalMessage> invalidProposals,
                                     int consensusId);
}