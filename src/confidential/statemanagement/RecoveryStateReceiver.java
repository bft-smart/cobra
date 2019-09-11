package confidential.statemanagement;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;

/**
 * @author Robin
 */
public class RecoveryStateReceiver extends Thread {
    private SSLSocket socket;

    public RecoveryStateReceiver(RecoveryStateServerSMMessage serverInfo, StateRecoveryHandler stateRecoveryHandler) throws IOException {
        super("RecoveryStateReceiver");
        this.socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(serverInfo.getServerIp(),
                serverInfo.getServerPort());
    }

    @Override
    public void run() {

    }
}
