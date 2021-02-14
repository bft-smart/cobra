package confidential.polynomial;

public abstract class PolynomialManagerContext {
    protected final int id;
    protected final int nPolynomials;
    private long startTime;
    private long endTime;
    protected int currentIndex;
    private int lastCID;

    public PolynomialManagerContext(int id, int nPolynomials) {
        this.id = id;
        this.nPolynomials = nPolynomials;
    }

    public void setCID(int cid) {
        lastCID = Math.max(cid, lastCID);
    }

    public int getLastCID() {
        return lastCID;
    }

    public int getId() {
        return id;
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

    public long getTime() {
        return endTime - startTime;
    }
}
