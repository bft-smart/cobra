package confidential.benchmark;

import bftsmart.tom.ServiceProxy;
import bftsmart.tom.util.Extractor;
import confidential.ExtractedResponse;
import confidential.MessageType;
import confidential.client.ClientConfidentialityScheme;
import confidential.client.ConfidentialComparator;
import confidential.client.ConfidentialExtractor;
import confidential.client.Response;
import confidential.demo.map.client.Operation;
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
import java.util.Random;

/**
 * @author Robin
 */
public class PreComputedProxy {
    private final Logger logger = LoggerFactory.getLogger("confidential");

    private final ServiceProxy service;
    private final ClientConfidentialityScheme confidentialityScheme;
    private byte[] orderedRequest;
    private byte[] unorderedRequest;
    public byte[] plainReadData;
    public byte[] plainWriteData;
    public byte[] data;
    private boolean preComputed;

    public PreComputedProxy(int clientId, int requestSize, boolean preComputed) throws SecretSharingException {
        this.preComputed = preComputed;
        Extractor extractor = new ConfidentialExtractor();
        Comparator<byte[]> comparator = new ConfidentialComparator();

        this.service = new ServiceProxy(clientId, null, comparator, extractor, null);
        this.confidentialityScheme = new ClientConfidentialityScheme(service.getViewManager().getCurrentView());
        preComputeRequests(clientId, requestSize);
    }

    private void preComputeRequests(int clientId, int requestSize) throws SecretSharingException {
        Random random = new Random(1L);
        String key = "k" + clientId;
        data = new byte[requestSize];
        random.nextBytes(data);
        plainWriteData = serialize(Operation.PUT, key);
        plainReadData = serialize(Operation.GET, key);
        orderedRequest = composeRequest(plainWriteData, data);
        unorderedRequest = composeRequest(plainReadData);
    }

    private byte[] serialize(Operation op, String str) {
        try(ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutput out = new ObjectOutputStream(bos)) {
            out.write((byte)op.ordinal());
            if(str != null)
                out.writeUTF(str);
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public Response invokeOrdered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        byte[] request = preComputed ? orderedRequest : composeRequest(plainData, confidentialData);
        if (request == null)
            return null;

        byte[] response = service.invokeOrdered(request);

        return preComputed ? null : composeResponse(response);
    }

    public Response invokeUnordered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        byte[] request = preComputed ? unorderedRequest : composeRequest(plainData, confidentialData);
        if (request == null)
            return null;

        byte[] response = service.invokeUnordered(request);

        return preComputed ? null : composeResponse(response);
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
