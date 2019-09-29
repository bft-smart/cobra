package confidential.statemanagement;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.util.TOMUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitments;
import vss.secretsharing.Share;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;

/**
 * @author Robin
 */
public class RecoveryStateReceiver extends Thread {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private static final String SECRET = "MySeCreT_2hMOygBwY";
    private SSLSocketFactory socketFactory;
    private StateRecoveryHandler stateRecoveryHandler;
    private BlockingQueue<RecoveryStateServerSMMessage> recoveryHelperServers;
    private ServerViewController svController;
    private MessageDigest digest;

    public RecoveryStateReceiver(StateRecoveryHandler stateRecoveryHandler,
                                 ServerViewController svController) throws IOException, UnrecoverableKeyException,
            CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        super("RecoveryStateReceiver");
        this.stateRecoveryHandler = stateRecoveryHandler;
        this.svController = svController;
        this.recoveryHelperServers = new LinkedBlockingDeque<>();
        this.socketFactory = getSSLSocketFactory(svController);
        this.digest = TOMUtil.getHashEngine();
    }

    private SSLSocketFactory getSSLSocketFactory(ServerViewController svController) throws CertificateException,
            UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        try (FileInputStream fis = new FileInputStream("config/keysSSL_TLS/" +
                svController.getStaticConf().getSSLTLSKeyStore())) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(fis, SECRET.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(ks, SECRET.toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
            trustManagerFactory.init(ks);

            SSLContext context = SSLContext.getInstance(svController.getStaticConf().getSSLTLSProtocolVersion());
            context.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            return context.getSocketFactory();
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException
                | UnrecoverableKeyException | KeyManagementException e) {
            logger.error("Failed to initialize SSL attributes", e);
            throw e;
        }
    }

    void addRecoveryStateMessage(RecoveryStateServerSMMessage msg) {
        try {
            recoveryHelperServers.put(msg);
        } catch (InterruptedException e) {
            logger.error("Failed to add recovery state message", e);
        }
    }

    @Override
    public void run() {
        while (true) {
            try {
                RecoveryStateServerSMMessage serverInfo = recoveryHelperServers.take();
                logger.info("Connecting to {} to ask recovery state ({}:{})", serverInfo.getSender(),
                        serverInfo.getServerIp(), serverInfo.getServerPort());
                SSLSocket socket = (SSLSocket) socketFactory.createSocket(
                        serverInfo.getServerIp(), serverInfo.getServerPort());
                socket.setKeepAlive(true);
                socket.setTcpNoDelay(true);
                socket.setEnabledCipherSuites(svController.getStaticConf().getEnabledCiphers());

                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

                long t1 = System.nanoTime();

                Commitments commitments = new Commitments();
                commitments.readExternal(in);
                int lastCheckpointCID = in.readInt();
                int lastCID = in.readInt();
                int pid = in.readInt();
                LinkedList<Share> shares = new LinkedList<>();
                int nShares = in.readInt();
                while (nShares-- > 0) {
                    Share share = new Share();
                    share.readExternal(in);
                    shares.add(share);
                }

                byte[] commonState = null;
                byte[] commonStateHash;

                if (in.readBoolean()) {
                    int nCommonStateBytes = in.readInt();
                    commonState = new byte[nCommonStateBytes];
                    int i = 0;

                    while (i < nCommonStateBytes) {
                        int len = Math.min(1024, nCommonStateBytes - i);
                        in.readFully(commonState, i, len);
                        digest.update(commonState, i, len);
                        //logger.debug("{}", Arrays.toString(Arrays.copyOfRange(commonState, i, len)));
                        i += len;
                    }

                    commonStateHash = digest.digest();

                    if (!Arrays.equals(commonStateHash, TOMUtil.computeHash(commonState))) {
                        logger.error("=========================================>   ERROROROROROROROR");
                    } else  {
                        logger.error("=========================================>   YESSSSSSSSSSSSSSS");
                    }
                } else {
                    commonStateHash = new byte[in.readInt()];
                    in.readFully(commonStateHash);
                }

                RecoveryApplicationState recoveryApplicationState = new RecoveryApplicationState(
                        commonState,
                        commonStateHash,
                        shares,
                        lastCheckpointCID,
                        lastCID,
                        pid,
                        commitments
                );

                long t2 = System.nanoTime();

                logger.info("Recovery state received from {} and took {} ms",
                        serverInfo.getSender(), ((t2 - t1) / 1_000_000.0));
                socket.close();
                stateRecoveryHandler.deliverRecoveryStateMessage(recoveryApplicationState);
            } catch (InterruptedException e) {
                break;
            } catch (IOException e) {
                logger.error("Failed to receive state.", e);
            }
        }
        logger.debug("Exiting recovery state receiver thread");
    }
}
