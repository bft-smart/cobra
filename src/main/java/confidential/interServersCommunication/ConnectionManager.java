package confidential.interServersCommunication;

import bftsmart.communication.server.ServersCommunicationLayer;
import bftsmart.reconfiguration.ServerViewController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Simplified version of BFT-SMaRT's bftsmart.communication.server.ServersCommunicationLayer.java
 */
public class ConnectionManager extends Thread {
    private final Logger logger = LoggerFactory.getLogger("communication");
    private boolean doWork;
    private final ServerViewController svController;
    private final Lock connectionsLock;
    private final HashMap<Integer, Connection> connections;
    private final LinkedBlockingQueue<InternalMessage> inQueue;
    private final int me;

    private static final String SECRET = "MySeCreT_2hMOygBwY";
    private final SSLServerSocket serverSocketSSLTLS;

    public ConnectionManager(ServerViewController svController,
                             LinkedBlockingQueue<InternalMessage> inQueue) throws Exception{
        super("Connection Manager Thread");
        this.svController = svController;
        this.inQueue = inQueue;
        this.doWork = true;
        this.connectionsLock = new ReentrantLock(true);
        this.connections = new HashMap<>(svController.getCurrentViewN());
        String ssltlsProtocolVersion = svController.getStaticConf().getSSLTLSProtocolVersion();
        this.me = svController.getStaticConf().getProcessId();

        String myAddress;
        String confAddress =
                svController.getStaticConf().getRemoteAddress(me)
                        .getAddress().getHostAddress();

        if (InetAddress.getLoopbackAddress().getHostAddress().equals(confAddress)) {
            myAddress = InetAddress.getLoopbackAddress().getHostAddress();
        } else if (svController.getStaticConf().getBindAddress().equals("")) {
            myAddress = InetAddress.getLocalHost().getHostAddress();
            //If the replica binds to the loopback address, clients will not be able to connect to replicas.
            //To solve that issue, we bind to the address supplied in config/hosts.config instead.
            if (InetAddress.getLoopbackAddress().getHostAddress().equals(myAddress) && !myAddress.equals(confAddress)) {
                myAddress = confAddress;
            }
        } else {
            myAddress = svController.getStaticConf().getBindAddress();
        }

        int myPort = svController.getStaticConf().getServerToServerPort(me)
                + 1;

        KeyStore ks;
        try (FileInputStream fis = new FileInputStream("config/keysSSL_TLS/" + svController.getStaticConf().getSSLTLSKeyStore())) {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(fis, SECRET.toCharArray());
        }

        String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
        kmf.init(ks, SECRET.toCharArray());

        TrustManagerFactory trustMgrFactory = TrustManagerFactory.getInstance(algorithm);
        trustMgrFactory.init(ks);

        SSLContext context = SSLContext.getInstance(ssltlsProtocolVersion);
        context.init(kmf.getKeyManagers(), trustMgrFactory.getTrustManagers(), new SecureRandom());

        SSLServerSocketFactory serverSocketFactory = context.getServerSocketFactory();
        this.serverSocketSSLTLS = (SSLServerSocket) serverSocketFactory.createServerSocket(myPort, 100,
                InetAddress.getByName(myAddress));

        serverSocketSSLTLS.setEnabledCipherSuites(svController.getStaticConf().getEnabledCiphers());

        String[] ciphers = serverSocketFactory.getSupportedCipherSuites();
        for (String cipher : ciphers) {
            logger.trace("Supported Cipher: {} ", cipher);
        }

        serverSocketSSLTLS.setEnableSessionCreation(true);
        serverSocketSSLTLS.setReuseAddress(true);
        serverSocketSSLTLS.setNeedClientAuth(true);
        serverSocketSSLTLS.setWantClientAuth(true);


        //Try connecting if a member of the current view. Otherwise, wait until the Join has been processed!
        if (svController.isInCurrentView()) {
            int[] initialV = svController.getCurrentViewAcceptors();
            for (int j : initialV) {
                if (j != me) {
                    getConnection(j);
                }
            }
        }
    }

    public void send(CommunicationTag tag, InternalMessage message, int... targets) {
        try (ByteArrayOutputStream bOut = new ByteArrayOutputStream(512);
             ObjectOutput out = new ObjectOutputStream(bOut)) {
            message.writeExternal(out);
            out.flush();
            bOut.flush();
            byte[] data = bOut.toByteArray();

            List<Integer> targetIndexes = new ArrayList<>(targets.length);
            for (int i = 0; i < targets.length; i++) {
                targetIndexes.add(i);
            }
            Collections.shuffle(targetIndexes);

            for (int targetIndex : targetIndexes) {
                int target = targets[targetIndex];
                if (target == me) {
                    inQueue.put(message);
                    logger.debug("Queueing (delivering) my own message with tag {}", tag);
                } else {
                    logger.debug("Sending message to {} with tag {}", target, tag);
                    getConnection(target).send(data);
                }
            }
        } catch (IOException e) {
            logger.error("Failed to serialize message with tag {}", tag, e);
        } catch (InterruptedException e) {
            logger.error("Failed to insert message into inQueue", e);
        }
    }

    @Override
    public void run() {
        while (doWork) {
            try {
                SSLSocket newSocket = (SSLSocket) serverSocketSSLTLS.accept();
                setSSLSocketOptions(newSocket);
                int remoteId = new DataInputStream(newSocket.getInputStream()).readInt();
                logger.debug("Trying to establish connection with replica {}", remoteId);
                establishConnection(newSocket, remoteId);
            } catch (SocketTimeoutException ignored) {
                logger.trace("Server socket timed out, retrying");
            } catch (SSLHandshakeException e) {
                e.printStackTrace();
            } catch (IOException e) {
                logger.error("Problem during thread execution", e);
            }
        }
        try {
            serverSocketSSLTLS.close();
        } catch (IOException e) {
            logger.error("Failed to close server socket", e);
        }

        logger.debug("Exiting Connection Manager");
    }

    public void shutdown() {
        logger.debug("Shutting down connection manager");

        doWork = false;

        int[] activeServers = svController.getCurrentViewAcceptors();
        for (int activeServer : activeServers) {
            if (me != activeServer) {
                getConnection(activeServer).shutdown();
            }
        }
    }

    private Connection getConnection(int remoteId) {
        connectionsLock.lock();
        Connection ret = this.connections.get(remoteId);
        if (ret == null) {
            ret = new Connection(svController, remoteId, null, inQueue);
            this.connections.put(remoteId, ret);
        }
        connectionsLock.unlock();
        return ret;
    }

    private void establishConnection(SSLSocket newSocket, int remoteId) throws IOException {
        if ((svController.getStaticConf().getTTPId() == remoteId) || svController.isCurrentViewMember(remoteId)) {
            connectionsLock.lock();
            if (this.connections.get(remoteId) == null) { //This must never happen!!!
                //first time that this connection is being established
                //System.out.println("THIS DOES NOT HAPPEN....."+remoteId);
                this.connections.put(remoteId,
                        new Connection(svController, remoteId, newSocket, inQueue));
            } else {
                //reconnection
                logger.debug("ReConnecting with replica: {}", remoteId);
                this.connections.get(remoteId).reconnect(newSocket);
            }
            connectionsLock.unlock();

        } else {
            logger.debug("Closing connection with replica: {}", remoteId);
            newSocket.close();
        }
    }

    public static void setSSLSocketOptions(SSLSocket socket) {
        try {
            socket.setTcpNoDelay(true);
        } catch (SocketException ex) {
            LoggerFactory.getLogger(ServersCommunicationLayer.class).
                    error("Failed to set TCPNODELAY", ex);
        }
    }
}
