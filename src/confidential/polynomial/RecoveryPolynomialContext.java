package confidential.polynomial;

import vss.secretsharing.VerifiableShare;

public class RecoveryPolynomialContext extends PolynomialManagerContext {
    private final int f;
    private final VerifiableShare[] points;

    public RecoveryPolynomialContext(int id, int nPolynomials, int f) {
        super(id, nPolynomials);
        this.f = f;
        this.points = new VerifiableShare[nPolynomials];
    }

    public int getF() {
        return f;
    }

    public VerifiableShare[] getPoints() {
        return points;
    }

    public void addPolynomial(VerifiableShare point) {
        points[currentIndex++] = point;
    }
}
