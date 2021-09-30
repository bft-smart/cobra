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

    public void addPolynomial(int id, VerifiableShare... shares) {
        if (currentIndex == nPolynomials) {
            return;
        }
        int index = (super.id == 0 ? id : id % super.id) * shares.length;
        for (int i = 0; i < shares.length && index + i < nPolynomials; i++) {
            points[index + i] = shares[i];
            currentIndex++;
        }
    }
}
