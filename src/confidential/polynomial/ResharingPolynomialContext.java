package confidential.polynomial;

import confidential.polynomial.creator.ViewStatus;
import vss.secretsharing.VerifiableShare;

public class ResharingPolynomialContext extends PolynomialManagerContext {
    private final int oldF;
    private final int newF;
    private final int[] oldMembers;
    private final int[] newMembers;
    private final ViewStatus viewStatus;
    private final VerifiableShare[] pointsForOldGroup;
    private final VerifiableShare[] pointsForNewGroup;

    public ResharingPolynomialContext(int id, int nPolynomials, int oldF,
                                      int newF, int[] oldMembers, int[] newMembers,
                                      ViewStatus viewStatus) {
        super(id, nPolynomials);
        this.oldF = oldF;
        this.newF = newF;
        this.oldMembers = oldMembers;
        this.newMembers = newMembers;
        this.viewStatus = viewStatus;
        switch (viewStatus) {
            case IN_NEW:
                pointsForOldGroup = null;
                pointsForNewGroup = new VerifiableShare[nPolynomials];
                break;
            case IN_OLD:
                pointsForOldGroup = new VerifiableShare[nPolynomials];
                pointsForNewGroup = null;
                break;
            case IN_BOTH:
                pointsForOldGroup = new VerifiableShare[nPolynomials];
                pointsForNewGroup = new VerifiableShare[nPolynomials];
                break;
            default:
                pointsForNewGroup = null;
                pointsForOldGroup = null;
                throw new IllegalStateException("Unknown view status");
        }
    }

    public int getOldF() {
        return oldF;
    }

    public int getNewF() {
        return newF;
    }

    public int[] getOldMembers() {
        return oldMembers;
    }

    public int[] getNewMembers() {
        return newMembers;
    }

    public VerifiableShare[] getPointsForNewGroup() {
        return pointsForNewGroup;
    }

    public VerifiableShare[] getPointsForOldGroup() {
        return pointsForOldGroup;
    }

    public void addPolynomial(VerifiableShare[] points) {
        switch (viewStatus) {
            case IN_NEW:
                if (pointsForNewGroup == null)
                    throw new IllegalStateException("Points holder for new group is null");
                pointsForNewGroup[currentIndex] = points[0];
                break;
            case IN_OLD:
                if (pointsForOldGroup == null)
                    throw new IllegalStateException("Points holder for old group is null");
                pointsForOldGroup[currentIndex] = points[0];
                break;
            case IN_BOTH:
                if (pointsForOldGroup == null || pointsForNewGroup == null)
                    throw new IllegalStateException("Points holder for old or new group is null");
                pointsForOldGroup[currentIndex] = points[0];
                pointsForNewGroup[currentIndex] = points[1];
                break;
        }
        currentIndex++;
    }
}
