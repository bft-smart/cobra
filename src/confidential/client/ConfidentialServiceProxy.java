package confidential.client;

import bftsmart.tom.ServiceProxy;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.Extractor;
import confidential.ExtractedResponse;
import confidential.MessageType;
import confidential.encrypted.EncryptedConfidentialData;
import confidential.encrypted.EncryptedConfidentialMessage;
import confidential.encrypted.EncryptedVerifiableShare;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.PrivatePublishedShares;
import vss.secretsharing.Share;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.*;

public class ConfidentialServiceProxy implements Comparator<byte[]>, Extractor {
    private final Logger logger = LoggerFactory.getLogger("confidential");

    private final ServiceProxy service;
    private int clientId;
    private final ClientConfidentialityScheme confidentialityScheme;
    private final Map<byte[], EncryptedConfidentialMessage> responses;
    private final Map<EncryptedConfidentialMessage, Integer> responseHashes;
    private CommitmentScheme commitmentScheme;

    public ConfidentialServiceProxy(int clientId) throws SecretSharingException {
        this.service = new ServiceProxy(clientId, null, this, this, null);
        this.clientId = clientId;
        this.confidentialityScheme = new ClientConfidentialityScheme(service.getViewManager().getCurrentView());
        this.responses = new HashMap<>();
        this.responseHashes = new HashMap<>();
        this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
    }

    private void reset() {
        this.responses.clear();
        this.responseHashes.clear();
    }

    public Response invokeOrdered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        reset();
        byte[] request = composeRequest(plainData, confidentialData);
        if (request == null)
            return null;

        byte[] response = service.invokeOrdered(request);

        return composeResponse(response);
    }

    public Response invokeUnordered(byte[] plainData, byte[]... confidentialData) throws SecretSharingException {
        reset();
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

    @Override
    public int compare(byte[] o1, byte[] o2) {
        EncryptedConfidentialMessage response1 = responses.computeIfAbsent(o1,
                EncryptedConfidentialMessage::deserialize);
        EncryptedConfidentialMessage response2 = responses.computeIfAbsent(o2, EncryptedConfidentialMessage::deserialize);
        if (response1 == null && response2 == null)
            return 0;
        if (response1 == null)
            return 1;
        if (response2 == null)
            return -1;
        int hash1 = responseHashes.computeIfAbsent(response1, EncryptedConfidentialMessage::hashCode);
        int hash2 = responseHashes.computeIfAbsent(response2, EncryptedConfidentialMessage::hashCode);
        return hash1 - hash2;
    }

    @Override
    public TOMMessage extractResponse(TOMMessage[] replies, int sameContent, int lastReceived) {
        EncryptedConfidentialMessage response;
        Map<Integer, LinkedList<EncryptedConfidentialMessage>> msgs = new HashMap<>();
        for (TOMMessage msg : replies) {
            if (msg == null)
                continue;
            response = responses.get(msg.getContent());
            if (response == null) {
                logger.warn("Something went wrong while getting deserialized response from {}", msg.getSender());
                continue;
            }
            int responseHash = responseHashes.get(response);

            LinkedList<EncryptedConfidentialMessage> msgList = msgs.computeIfAbsent(responseHash, k -> new LinkedList<>());
            msgList.add(response);
        }

        for (LinkedList<EncryptedConfidentialMessage> msgList : msgs.values()) {
            if (msgList.size() == sameContent) {
                EncryptedConfidentialMessage firstMsg = msgList.getFirst();
                byte[] plainData = firstMsg.getPlainData();
                byte[][] confidentialData = null;

                if (firstMsg.getShares() != null) { // this response has secret data
                    int numSecrets = firstMsg.getShares().length;
                    ArrayList<LinkedList<EncryptedVerifiableShare>> verifiableShares =
                            new ArrayList<>(numSecrets);
                    for (int i = 0; i < numSecrets; i++) {
                        verifiableShares.add(new LinkedList<>());
                    }
                    confidentialData = new byte[numSecrets][];

                    for (EncryptedConfidentialMessage confidentialMessage : msgList) {
                        EncryptedConfidentialData[] sharesI =
                                confidentialMessage.getShares();
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
                        LinkedList<EncryptedVerifiableShare> secretI = verifiableShares.get(i);
                        shares = new Share[secretI.size()];
                        Map<BigInteger, Commitment> commitmentsToCombine =
                                new HashMap<>(secretI.size());
                        shareData = secretI.getFirst().getSharedData();
                        int k = 0;
                        for (EncryptedVerifiableShare verifiableShare : secretI) {
                            try {
                                shares[k] =
                                        confidentialityScheme.decryptShare(clientId,
                                                verifiableShare.getShare());
                            } catch (SecretSharingException e) {
                                logger.error("Failed to decrypt share of {}",
                                        verifiableShare.getShare().getShareholder(), e);
                            }
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
        logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
        return null;
    }
}
