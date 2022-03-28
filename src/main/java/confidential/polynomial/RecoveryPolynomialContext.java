package confidential.polynomial;

import vss.secretsharing.VerifiableShare;

public class RecoveryPolynomialContext extends PolynomialManagerContext {
    private final int f;
    private final VerifiableShare[] points;

    public RecoveryPolynomialContext(int initialId, int nPolynomials, int f) {
        super(initialId, nPolynomials);
        this.f = f;
        this.points = new VerifiableShare[nPolynomials];
    }

    public int getF() {
        return f;
    }

    public VerifiableShare[] getPoints() {
        return points;
    }

    public void addPolynomial(int id, VerifiableShare... shares) {
        if (currentSize == nPolynomials) {
            return;
        }
        int index = (id - initialId) * shares.length;
        for (int i = 0; i < shares.length && index + i < nPolynomials; i++) {
            points[index + i] = shares[i];
            currentSize++;
        }
    }
}
