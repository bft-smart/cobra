package confidential.polynomial;

public interface RecoveryPolynomialListener {
    void onRecoveryPolynomialsFailure(RecoveryPolynomialContext context);
    void onRecoveryPolynomialsCreation(RecoveryPolynomialContext context);
}
