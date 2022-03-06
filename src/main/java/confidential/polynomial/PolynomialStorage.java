package confidential.polynomial;

import vss.secretsharing.VerifiableShare;

import java.util.HashMap;
import java.util.Map;

/**
 * @author robin
 */
public class PolynomialStorage {
	private final Map<Integer, VerifiableShare[]> points;

	public PolynomialStorage() {
		this.points = new HashMap<>();
	}

	public void putPoints(int id, VerifiableShare[] newPoints) {
		points.put(id, newPoints);
	}

	public VerifiableShare[] getPoints(int id) {
		return points.get(id);
	}
}
