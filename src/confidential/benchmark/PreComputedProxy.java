package confidential.benchmark;

import bftsmart.tom.ServiceProxy;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.Extractor;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.ExtractedResponse;
import confidential.MessageType;
import confidential.client.ClientConfidentialityScheme;
import confidential.client.ConfidentialComparator;
import confidential.client.ConfidentialExtractor;
import confidential.client.Response;
import confidential.demo.map.client.Operation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.PrivatePublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.*;

/**
 * @author Robin
 */
public class PreComputedProxy implements Comparator<byte[]>, Extractor {
    private final Logger logger = LoggerFactory.getLogger("confidential");

    private final ServiceProxy service;
    private final ClientConfidentialityScheme confidentialityScheme;
    private byte[] orderedRequest;
    private byte[] unorderedRequest;
    byte[] plainReadData;
    byte[] plainWriteData;
    public byte[] data;
    private boolean preComputed;
    private final Map<byte[], ConfidentialMessage> responses;
    private final Map<ConfidentialMessage, Integer> responseHashes;
    private CommitmentScheme commitmentScheme;

    PreComputedProxy(int clientId, int requestSize, boolean preComputed) throws SecretSharingException {
        this.preComputed = preComputed;
        this.service = new ServiceProxy(clientId, null, this, this,
                null);
        this.confidentialityScheme = new ClientConfidentialityScheme(service.getViewManager().getCurrentView());
        this.responses = new HashMap<>();
        this.responseHashes = new HashMap<>();
        this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
        preComputeRequests(clientId, requestSize);
    }

    private void reset() {
        this.responses.clear();
        this.responseHashes.clear();
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

        logger.info("plain write data size: {}", plainWriteData.length);
        logger.info("plain read data size: {}", plainReadData.length);
        logger.info("ordered request size: {} bytes", orderedRequest.length);
        logger.info("unordered request size: {} bytes", unorderedRequest.length);
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

    Response invokeOrdered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        reset();
        byte[] request = preComputed ? orderedRequest : composeRequest(plainData, confidentialData);
        if (request == null)
            return null;

        byte[] response = service.invokeOrdered(request);

        return preComputed ? null : composeResponse(response);
    }

    Response invokeUnordered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        reset();
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

    @Override
    public int compare(byte[] o1, byte[] o2) {
        ConfidentialMessage response1 = responses.computeIfAbsent(o1, ConfidentialMessage::deserialize);
        ConfidentialMessage response2 = responses.computeIfAbsent(o2, ConfidentialMessage::deserialize);
        if (response1 == null && response2 == null)
            return 0;
        if (response1 == null)
            return 1;
        if (response2 == null)
            return -1;
        int hash1 = responseHashes.computeIfAbsent(response1, ConfidentialMessage::hashCode);
        int hash2 = responseHashes.computeIfAbsent(response2, ConfidentialMessage::hashCode);
        return hash1 - hash2;
    }

    @Override
    public TOMMessage extractResponse(TOMMessage[] replies, int sameContent, int lastReceived) {
        if (preComputed)
            return replies[lastReceived];
        ConfidentialMessage response;
        Map<Integer, LinkedList<ConfidentialMessage>> msgs = new HashMap<>();
        for (TOMMessage msg : replies) {
            if (msg == null)
                continue;
            response = responses.get(msg.getContent());
            if (response == null) {
                logger.warn("Something went wrong while getting deserialized response from {}", msg.getSender());
                continue;
            }
            int responseHash = responseHashes.get(response);

            LinkedList<ConfidentialMessage> msgList = msgs.computeIfAbsent(responseHash, k -> new LinkedList<>());
            msgList.add(response);
        }

        for (LinkedList<ConfidentialMessage> msgList : msgs.values()) {
            if (msgList.size() == sameContent) {
                ConfidentialMessage firstMsg = msgList.getFirst();
                byte[] plainData = firstMsg.getPlainData();
                byte[][] confidentialData = null;

                if (firstMsg.getShares() != null) { // this response has secret data
                    int numSecrets = firstMsg.getShares().length;
                    ArrayList<LinkedList<VerifiableShare>> verifiableShares = new ArrayList<>(numSecrets);
                    for (int i = 0; i < numSecrets; i++) {
                        verifiableShares.add(new LinkedList<>());
                    }
                    confidentialData = new byte[numSecrets][];

                    for (ConfidentialMessage confidentialMessage : msgList) {
                        ConfidentialData[] sharesI = confidentialMessage.getShares();
                        for (int i = 0; i < numSecrets; i++) {
                            verifiableShares.get(i).add(sharesI[i].getShare());
                            if (sharesI[i].getPublicShares() != null) {
                                verifiableShares.get(i).addAll(sharesI[i].getPublicShares());
                            }
                        }
                    }

                    byte[] shareData;
                    Share[] shares;
                    for (int i = 0; i < numSecrets; i++) {
                        LinkedList<VerifiableShare> secretI = verifiableShares.get(i);
                        shares = new Share[secretI.size()];
                        shareData = secretI.getFirst().getSharedData();
                        int k = 0;
                        Map<BigInteger, Commitment> commitmentsToCombine =
                                new HashMap<>(secretI.size());
                        for (VerifiableShare verifiableShare : secretI) {
                            shares[k] = verifiableShare.getShare();
                            commitmentsToCombine.put(
                                    verifiableShare.getShare().getShareholder(),
                                    verifiableShare.getCommitments());
                            k++;
                        }


                        Commitment commitment =
                                commitmentScheme.combineCommitments(commitmentsToCombine);
                        OpenPublishedShares secret = new OpenPublishedShares(shares, commitment, shareData);
                        try {
                            confidentialData[i] = confidentialityScheme.combine(secret);
                        } catch (SecretSharingException e) {
                            ExtractedResponse extractedResponse = new ExtractedResponse(plainData, confidentialData, e);
                            TOMMessage lastMsg = replies[lastReceived];
                            return new TOMMessage(lastMsg.getSender(),
                                    lastMsg.getSession(), lastMsg.getSequence(),
                                    lastMsg.getOperationId(), extractedResponse.serialize(),
                                    lastMsg.getViewID(), lastMsg.getReqType());
                        }
                    }
                }
                ExtractedResponse extractedResponse = new ExtractedResponse(plainData, confidentialData);
                TOMMessage lastMsg = replies[lastReceived];
                return new TOMMessage(lastMsg.getSender(),
                        lastMsg.getSession(), lastMsg.getSequence(),
                        lastMsg.getOperationId(), extractedResponse.serialize(),
                        lastMsg.getViewID(), lastMsg.getReqType());

            }
        }
        logger.error("This should not happen.");
        return null;
    }
}
