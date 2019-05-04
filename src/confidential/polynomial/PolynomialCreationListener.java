package confidential.polynomial;

import vss.secretsharing.VerifiableShare;

public interface PolynomialCreationListener {
    void onPolynomialCreation(PolynomialCreationReason reason, int id, VerifiableShare point);
}
