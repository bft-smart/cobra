package confidential.polynomial;

import vss.secretsharing.VerifiableShare;

public interface PolynomialCreationListener {
    void onPolynomialCreation(PolynomialContext context, VerifiableShare point);
}
