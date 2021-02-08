package confidential.polynomial;

public abstract class PolynomialManagerContext {
    private final int id;
    private final int nPolynomials;
    private long startTime;
    private long endTime;
    protected int currentIndex;

    public PolynomialManagerContext(int id, int nPolynomials) {
        this.id = id;
        this.nPolynomials = nPolynomials;
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
