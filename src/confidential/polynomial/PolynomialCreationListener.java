package confidential.polynomial;

import vss.secretsharing.VerifiableShare;

import java.util.List;

public interface PolynomialCreationListener {
    void onPolynomialCreationSuccess(PolynomialContext context, VerifiableShare point,
                                     int consensusId);
    void onPolynomialCreationFailure(PolynomialContext context,
                                     List<ProposalMessage> invalidProposals,
                                     int consensusId);
}
