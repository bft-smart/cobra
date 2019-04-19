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
        this.confidentialityScheme = new ClientConfidentialityScheme(service.getViewManager().getCurrentViewF(),
                service.getViewManager().getCurrentViewProcesses());
    }

    public Response invokeOrdered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        byte[] request = composeRequest(plainData, confidentialData);
        if (request == null)
            return null;

        byte[] response = service.invokeOrdered(request);

        return composeResponse(response);
    }

    public void close() {
        service.close();
    }

    private Response composeResponse(byte[] response) throws SecretSharingException {
        if (response == null)
            return null;
        ExtractedResponse extractedResponse = ExtractedResponse.deserialize(response);
        OpenPublishedShares[] openShares = extractedResponse.getOpenShares();
        byte[][] confidentialData = new byte[openShares.length][];
        for (int i = 0; i < openShares.length; i++)
            confidentialData[i] = confidentialityScheme.combine(openShares[i]);
        return new Response(extractedResponse.getPlainData(), confidentialData);
    }

    private byte[] composeRequest(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            MessageType type = getMessageType(plainData, confidentialData);

            out.write((byte)type.ordinal());
            PrivatePublishedShares privateShares;

            switch (type) {
                case EMPTY:
                    break;
                case PLAIN:
                    out.writeInt(plainData.length);
                    out.write(plainData);
                    break;
                case SINGLE:
                    privateShares = confidentialityScheme.share(confidentialData[0]);
                    privateShares.writeExternal(out);
                    break;
                case MULTIPLE:
                    out.writeInt(confidentialData.length);
                    for (byte[] secret : confidentialData) {
                        privateShares = confidentialityScheme.share(secret);
                        privateShares.writeExternal(out);
                    }
                    break;
                case PLAIN_SINGLE:
                    out.writeInt(plainData.length);
                    out.write(plainData);
                    privateShares = confidentialityScheme.share(confidentialData[0]);
                    privateShares.writeExternal(out);
                    break;
                case PLAIN_MULTIPLE:
                    out.writeInt(plainData.length);
                    out.write(plainData);
                    out.writeInt(confidentialData.length);
                    for (byte[] secret : confidentialData) {
                        privateShares = confidentialityScheme.share(secret);
                        privateShares.writeExternal(out);
                    }
                    break;
                default:
                    logger.warn("Invalid request type");
            }
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            logger.error("Occurred while composing request", e);
            return null;
        }
    }

    private MessageType getMessageType(byte[] plainData, byte[][] confidentialData) {
        if (plainData != null && confidentialData != null) {
            if (confidentialData.length == 1)
                return MessageType.PLAIN_SINGLE;
            else
                return MessageType.PLAIN_MULTIPLE;
        }
        if (plainData != null)
            return MessageType.PLAIN;
        if (confidentialData != null)
            return confidentialData.length == 1 ? MessageType.SINGLE : MessageType.MULTIPLE;
        return MessageType.EMPTY;
    }
}
