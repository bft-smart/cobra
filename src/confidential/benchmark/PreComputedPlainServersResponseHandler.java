package confidential.benchmark;

import bftsmart.tom.core.messages.TOMMessage;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.ExtractedResponse;
import confidential.client.ServersResponseHandler;
import vss.commitment.Commitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

/**
 * @author Robin
 */
public class PreComputedPlainServersResponseHandler extends ServersResponseHandler {
    private final Map<byte[], ConfidentialMessage> responses;
    private final Map<ConfidentialMessage, Integer> responseHashes;
    private final boolean preComputed;

    public PreComputedPlainServersResponseHandler(boolean preComputed) {
        this.preComputed = preComputed;
        responses = new HashMap<>();
        responseHashes = new HashMap<>();
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
                    ArrayList<LinkedList<VerifiableShare>> verifiableShares =
                            new ArrayList<>(numSecrets);
                    for (int i = 0; i < numSecrets; i++) {
                        verifiableShares.add(new LinkedList<>());
                    }
                    confidentialData = new byte[numSecrets][];

                    for (ConfidentialMessage confidentialMessage : msgList) {
                        ConfidentialData[] sharesI =
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
                        LinkedList<VerifiableShare> secretI = verifiableShares.get(i);
                        shares = new Share[secretI.size()];
                        Map<BigInteger, Commitment> commitmentsToCombine =
                                new HashMap<>(secretI.size());
                        shareData = secretI.getFirst().getSharedData();
                        int k = 0;
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
                                    lastMsg.getOperationId(), extractedResponse.serialize(), new byte[0],
                                    lastMsg.getViewID(), lastMsg.getReqType());
                        }
                    }
                }
                ExtractedResponse extractedResponse = new ExtractedResponse(plainData, confidentialData);
                TOMMessage lastMsg = replies[lastReceived];
                return new TOMMessage(lastMsg.getSender(),
                        lastMsg.getSession(), lastMsg.getSequence(),
                        lastMsg.getOperationId(), extractedResponse.serialize(), new byte[0],
                        lastMsg.getViewID(), lastMsg.getReqType());

            }
        }
        logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
        return null;
    }

    @Override
    public int compare(byte[] o1, byte[] o2) {
        ConfidentialMessage response1 = responses.computeIfAbsent(o1,
                ConfidentialMessage::deserialize);
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
    public void reset() {
        responses.clear();
        responseHashes.clear();
    }
}
