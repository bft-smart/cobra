package confidential.polynomial;

import java.util.HashMap;
import java.util.Map;

public abstract class PolynomialManagerContext {
    protected final int initialId;
    protected final int nPolynomials;
    private long startTime;
    private long endTime;
    protected int currentSize;
    private Map<Integer, InvalidPolynomialContext> invalidPolynomialsContexts;
    private int maxCID;

    public PolynomialManagerContext(int initialId, int nPolynomials) {
        this.initialId = initialId;
        this.nPolynomials = nPolynomials;
    }

    public void updateCID(int cid) {
        maxCID = Math.max(cid, maxCID);
    }

    public int getMaxCID() {
        return maxCID;
    }

    public int getInitialId() {
        return initialId;
    }

    public int getNPolynomials() {
        return nPolynomials;
    }

    public void startTime() {
        startTime = System.nanoTime();
    }

    public void endTime() {
        endTime = System.nanoTime();
    }

    public Map<Integer, InvalidPolynomialContext> getInvalidPolynomialsContexts() {
        return invalidPolynomialsContexts;
    }

    public boolean containsInvalidPolynomials() {
        return invalidPolynomialsContexts != null;
    }

    public void addInvalidPolynomialProposals(int id, InvalidPolynomialContext invalidPolynomialContext) {
        if (invalidPolynomialsContexts == null) {
            invalidPolynomialsContexts = new HashMap<>();
        }
        invalidPolynomialsContexts.put(id - initialId, invalidPolynomialContext);
        currentSize += invalidPolynomialContext.getNInvalidPolynomials();
    }

    public long getTime() {
        return endTime - startTime;
    }
}
