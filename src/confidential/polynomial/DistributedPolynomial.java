package confidential.polynomial;

import bftsmart.reconfiguration.ServerViewController;
import confidential.MessageType;
import confidential.server.InterServersCommunication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

public class DistributedPolynomial {
    private Logger logger = LoggerFactory.getLogger("confidential");
    private InterServersCommunication serversCommunication;
    private ServerViewController svController;

    public DistributedPolynomial(InterServersCommunication serversCommunication, ServerViewController svController) {
        this.serversCommunication = serversCommunication;
        this.svController = svController;
    }

    public void createNewPolynomial(int f, BigInteger a, BigInteger b) {
        NewPolynomialMessage newPolynomialMessage = new NewPolynomialMessage(
                svController.getStaticConf().getProcessId(), f, a, b);
        byte[] request = serialize(newPolynomialMessage);
        if (request != null)
            serversCommunication.sendUnordered(request, svController.getCurrentViewAcceptors());
    }

    public void recievedMessage(PolynomialMessage message) {

    }

    private byte[] serialize(PolynomialMessage message) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.write((byte)MessageType.APPLICATION.ordinal());

            message.writeExternal(out);
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.warn("Polynomial message serialization failed", e);
        }
        return null;
    }
}
