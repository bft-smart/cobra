package confidential.client;

import bftsmart.tom.ServiceProxy;
import bftsmart.tom.util.Extractor;
import confidential.ExtractedResponse;
import confidential.MessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.PrivatePublishedShares;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.Comparator;

public class ConfidentialServiceProxy {
    private final Logger logger = LoggerFactory.getLogger("confidential");

    private final ServiceProxy service;
    private final ClientConfidentialityScheme confidentialityScheme;

    public ConfidentialServiceProxy(int clientId) throws SecretSharingException {
        Extractor extractor = new ConfidentialExtractor();
        Comparator<byte[]> comparator = new ConfidentialComparator();

        this.service = new ServiceProxy(clientId, null, comparator, extractor, null);
        this.confidentialityScheme = new ClientConfidentialityScheme(service.getViewManager().getCurrentView());
    }

    public Response invokeOrdered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        byte[] request = composeRequest(plainData, confidentialData);
        if (request == null)
            return null;

        byte[] response = service.invokeOrdered(request);

        return composeResponse(response);
    }

    public Response invokeUnordered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
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
        OpenPublishedShares[] openShares = extractedResponse.getOpenShares();
        byte[][] confidentialData = openShares != null ? new byte[openShares.length][] : null;
        if (openShares != null) {
            for (int i = 0; i < openShares.length; i++) {
                confidentialData[i] = confidentialityScheme.combine(openShares[i]);
            }
        }
        return new Response(extractedResponse.getPlainData(), confidentialData);
    }

    private byte[] composeRequest(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {

            out.write((byte)MessageType.CLIENT.ordinal());

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
