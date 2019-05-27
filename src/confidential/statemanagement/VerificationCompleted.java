package confidential.statemanagement;

public interface VerificationCompleted {
    void onVerificationCompleted(boolean valid, RecoverySMMessage state);
}
