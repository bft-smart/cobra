package confidential.interServersCommunication;

public interface InterServerMessageListener {
    void messageReceived(InterServersMessageType type, byte[] message);
}
