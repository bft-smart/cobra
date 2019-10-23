package confidential.statemanagement;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.reconfiguration.views.View;
import confidential.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.secretsharing.Share;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

/**
 * @author Robin
 */
public class RecoveryPrivateStateReceiver extends Thread {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private static final String SECRET = "MySeCreT_2hMOygBwY";
    private StateRecoveryHandler stateRecoveryHandler;
    private ServerViewController svController;
    private Set<String> knownServersIps;
    private SSLServerSocket serverSocket;

    RecoveryPrivateStateReceiver(StateRecoveryHandler stateRecoveryHandler,
                                 ServerViewController svController, int serverPort) throws CertificateException,
            UnrecoverableKeyException, NoSuchAlgorithmException, IOException, KeyManagementException, KeyStoreException {
        super("RecoveryStateReceiver");
        this.stateRecoveryHandler = stateRecoveryHandler;
        this.svController = svController;
        this.serverSocket = createSSLServerSocket(serverPort, svController);
        View currentView = svController.getCurrentView();
        this.knownServersIps = new HashSet<>(currentView.getN());

        for (int process : currentView.getProcesses()) {
            String ip = currentView.getAddress(process).getAddress().getHostAddress();
            knownServersIps.add(ip);
        }
    }

    private SSLServerSocket createSSLServerSocket(int serverPort, ServerViewController svController)
            throws IOException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException,
            CertificateException, UnrecoverableKeyException {
        KeyStore ks;
        try (FileInputStream fis = new FileInputStream("config/keysSSL_TLS/" +
                svController.getStaticConf().getSSLTLSKeyStore())) {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(fis, SECRET.toCharArray());
        }

        String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
        kmf.init(ks, SECRET.toCharArray());

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
        trustManagerFactory.init(ks);

        SSLContext context = SSLContext.getInstance(svController.getStaticConf().getSSLTLSProtocolVersion());
        context.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

        SSLServerSocketFactory serverSocketFactory = context.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(serverPort);
        serverSocket.setEnabledCipherSuites(svController.getStaticConf().getEnabledCiphers());
        serverSocket.setEnableSessionCreation(true);
        serverSocket.setReuseAddress(true);
        serverSocket.setNeedClientAuth(true);
        serverSocket.setWantClientAuth(true);

        return serverSocket;
    }

    @Override
    public void run() {
        while (true) {
            try (SSLSocket client = (SSLSocket) serverSocket.accept()) {
                client.setKeepAlive(true);
                client.setTcpNoDelay(true);
                client.setEnabledCipherSuites(svController.getStaticConf().getEnabledCiphers());

                String clientIp = client.getInetAddress().getHostAddress();
                if (!knownServersIps.contains(clientIp)) {
                    logger.info("Received connection from unknown server with ip {}", clientIp);
                    continue;
                }
                BufferedInputStream in = new BufferedInputStream(client.getInputStream());
                int pid = Utils.toNumber(Utils.readNBytes(4, in));
                logger.info("Received secure connection from {}", pid);

                long t1 = System.nanoTime();
                int len = Utils.toNumber(Utils.readNBytes(4, in));
                byte[] serializedPrivateState = Utils.readNBytes(len, in);
                long t2 = System.nanoTime();
                logger.info("Took {} ms to receive private state from {}", (t2 - t1) / 1_000_000.0, pid);
                in.close();
                LinkedList<Share> privateState = deserializePrivateState(pid, serializedPrivateState);
                if (privateState != null) {
                    logger.info("Replica {} sent me private state with {} shares", pid, privateState.size());
                    stateRecoveryHandler.deliverPrivateState(pid, privateState);
                }
            } catch (IOException e) {
                break;
            }
        }

        logger.debug("Exiting private state receiver thread");
    }

    private LinkedList<Share> deserializePrivateState(int from, byte[] serializedPrivateState) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(serializedPrivateState);
             ObjectInput in = new ObjectInputStream(bis)) {
            int nShares = in.readInt();
            LinkedList<Share> shares = new LinkedList<>();
            while (nShares-- > 0) {
                Share share = new Share();
                share.readExternal(in);
                shares.add(share);
            }

            return shares;
        } catch (IOException e) {
            logger.error("Failed to deserialize private state from {}", from);
            return null;
        }
    }

    @Override
    public void interrupt() {
        try {
            serverSocket.close();
        } catch (IOException e) {
            logger.error("Failed to close socket");
        }
        super.interrupt();
    }
}
