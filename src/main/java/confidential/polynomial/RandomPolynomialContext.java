package confidential.polynomial;

import vss.secretsharing.VerifiableShare;

/**
 * @author robin
 */
public class RandomPolynomialContext extends PolynomialManagerContext {
	private final int f;
	private VerifiableShare point;

	public RandomPolynomialContext(int id, int nPolynomials, int f) {
		super(id, nPolynomials);
		this.f = f;
	}

	public int getF() {
		return f;
	}

	public VerifiableShare getPoint() {
		return point;
	}

	public void setPoint(VerifiableShare point) {
		this.point = point;
	}
}
