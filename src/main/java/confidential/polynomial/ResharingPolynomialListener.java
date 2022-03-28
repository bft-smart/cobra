package confidential.polynomial;

public interface ResharingPolynomialListener {
    void onResharingPolynomialsFailure(ResharingPolynomialContext context);
    void onResharingPolynomialsCreation(ResharingPolynomialContext context);
}
