package confidential.interServersCommunication;

public interface InterServerMessageListener {
    void messageReceived(InterServerMessageHolder holder);
}
