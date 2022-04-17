package confidential.client;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.ExtractedResponse;
import confidential.ConfidentialMessage;
import confidential.ConfidentialExtractedResponse;
import vss.commitment.Commitment;
import vss.facade.Mode;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.math.BigInteger;
import java.util.*;

/**
 * @author Robin
 */
public class PlainServersResponseHandler extends ServersResponseHandler {
    private final Map<byte[], ConfidentialMessage> responses;
    private final Map<ConfidentialMessage, Integer> responseHashes;

    public PlainServersResponseHandler() {
        responses = new HashMap<>();
        responseHashes = new HashMap<>();
    }

    @Override
    public ExtractedResponse extractResponse(TOMMessage[] replies, int sameContent, int lastReceived) {
        TOMMessage lastMsg = replies[lastReceived];
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
                        VerifiableShare[] sharesI =
                                confidentialMessage.getShares();
                        for (int i = 0; i < numSecrets; i++) {
                            verifiableShares.get(i).add(sharesI[i]);
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
                            confidentialData[i] = confidentialityScheme.combine(secret,
                                    shareData == null ? Mode.SMALL_SECRET : Mode.LARGE_SECRET);
                        } catch (SecretSharingException e) {
                            return new ConfidentialExtractedResponse(lastMsg.getViewID(), plainData,
                                    confidentialData, e);
                            }
                    }
                }
                return new ConfidentialExtractedResponse(lastMsg.getViewID(), plainData, confidentialData);
            }
        }
        logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
        return null;
    }

    @Override
    public int compare(byte[] o1, byte[] o2) {
        if (o1 == null && o2 == null)
            return 0;
        ConfidentialMessage response1 = responses.computeIfAbsent(o1,
                ConfidentialMessage::deserialize);
        ConfidentialMessage response2 = responses.computeIfAbsent(o2, ConfidentialMessage::deserialize);
        if (response1 == null && response2 == null)
            return 0;
        if (response1 == null)
            return 1;
        if (response2 == null)
            return -1;
        int hash1 = responseHashes.computeIfAbsent(response1, this::computeSameSecretHash);
        int hash2 = responseHashes.computeIfAbsent(response2, this::computeSameSecretHash);
        return hash1 - hash2;
    }

    private int computeSameSecretHash(ConfidentialMessage message) {
        int result = Arrays.hashCode(message.getPlainData());
        VerifiableShare[] shares = message.getShares();
        if (shares != null) {
            for (VerifiableShare share : shares) {
                result = 31 * result + Arrays.hashCode(share.getSharedData());
                result = 31 * result + share.getCommitments().consistentHash();
            }
        }
        return result;
    }

    @Override
    public void reset() {
        responses.clear();
        responseHashes.clear();
    }
}
