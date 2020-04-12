package confidential.client;

import bftsmart.tom.ServiceProxy;
import confidential.Configuration;
import confidential.ExtractedResponse;
import confidential.MessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.facade.SecretSharingException;
import vss.secretsharing.PrivatePublishedShares;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;

public class ConfidentialServiceProxy {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private final ServiceProxy service;
    private final ClientConfidentialityScheme confidentialityScheme;
    private final ServersResponseHandler serversResponseHandler;

    public ConfidentialServiceProxy(int clientId) throws SecretSharingException {
        if (Configuration.getInstance().useTLSEncryption()) {
            serversResponseHandler = new PlainServersResponseHandler();
        } else {
            serversResponseHandler = new EncryptedServersResponseHandler(clientId);
        }
        this.service = new ServiceProxy(clientId, null, serversResponseHandler,
                serversResponseHandler, null);
        this.confidentialityScheme = new ClientConfidentialityScheme(service.getViewManager().getCurrentView());
        serversResponseHandler.setClientConfidentialityScheme(confidentialityScheme);

    }

    public Response invokeOrdered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
        byte[] request = composeRequest(plainData, confidentialData);
        if (request == null)
            return null;

        byte[] response = service.invokeOrdered(request);

        return composeResponse(response);
    }

    public Response invokeUnordered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        serversResponseHandler.reset();
        byte[] request = composeRequest(plainData, confidentialData);
        if (request == null)
            return null;

        byte[] response = service.invokeUnordered(request);

        return composeResponse(response);
    }

    public void close() {
        service.close();
    }

    private Response composeResponse(byte[] response) throws SecretSharingException {
        if (response == null)
            return null;
        ExtractedResponse extractedResponse = ExtractedResponse.deserialize(response);
        if (extractedResponse == null)
            return null;
        if (extractedResponse.getThrowable() != null)
            throw extractedResponse.getThrowable();
        return new Response(extractedResponse.getPlainData(), extractedResponse.getConfidentialData());
    }

    private byte[] composeRequest(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {

            out.write((byte) MessageType.CLIENT.ordinal());

            out.writeInt(plainData == null ? -1 : plainData.length);
            if (plainData != null)
                out.write(plainData);

            out.writeInt(confidentialData == null ? -1 : confidentialData.length);
            if (confidentialData != null) {
                PrivatePublishedShares privateShares;
                for (byte[] secret : confidentialData) {
                    privateShares = confidentialityScheme.share(secret);
                    privateShares.writeExternal(out);
                }
            }

            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Occurred while composing request", e);
            return null;
        }
    }
}
