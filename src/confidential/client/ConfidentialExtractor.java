package confidential.client;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.Extractor;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.ExtractedResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

public class ConfidentialExtractor implements Extractor {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private Map<Integer, LinkedList<ConfidentialMessage>> responses;

    public ConfidentialExtractor() {
        responses = new HashMap<>();
    }


    @Override
    public TOMMessage extractResponse(TOMMessage[] tomMessages, int sameContent, int lastReceived) {
        responses.clear();
        ConfidentialMessage response;

        for (TOMMessage msg : tomMessages) {
            if (msg == null)
                continue;
            response = ConfidentialMessage.deserialize(msg.getContent());
            if (response == null) {
                logger.warn("Something went wrong while deserializing response from {}", msg.getSender());
                continue;
            }
            int responseHash = response.hashCode();
            logger.debug("Response from {} with hash {}: {}", msg.getSender(), responseHash, response);
            if (!responses.containsKey(responseHash)) {
                LinkedList<ConfidentialMessage> msgList = new LinkedList<>();
                msgList.add(response);
                responses.put(responseHash, msgList);
            } else
                responses.get(responseHash).add(response);
        }

        for (LinkedList<ConfidentialMessage> msgList : responses.values()) {
            if (msgList.size() == sameContent) {
                ConfidentialMessage firstMsg = msgList.getFirst();
                byte[] plainData = firstMsg.getPlainData();

                OpenPublishedShares[] secrets = null;

                if (firstMsg.getShares() != null) { // this response has secret data
                    int numSecrets = firstMsg.getShares().length;
                    ArrayList<LinkedList<VerifiableShare>> verifiableShares = new ArrayList<>(numSecrets);
                    for (int i = 0; i < numSecrets; i++) {
                        verifiableShares.add(new LinkedList<>());
                    }
                    secrets = new OpenPublishedShares[numSecrets];

                    for (ConfidentialMessage confidentialMessage : msgList) {
                        ConfidentialData[] sharesI = confidentialMessage.getShares();
                        for (int i = 0; i < numSecrets; i++) {
                            verifiableShares.get(i).add(sharesI[i].getShare());
                            if (sharesI[i].getPublicShares() != null) {
                                verifiableShares.get(i).addAll(sharesI[i].getPublicShares());
                            }
                        }
                    }

                    Commitment commitments;
                    byte[] shareData;
                    Share[] shares;
                    for (int i = 0; i < numSecrets; i++) {
                        LinkedList<VerifiableShare> secretI = verifiableShares.get(i);
                        shares = new Share[secretI.size()];
                        commitments = secretI.getFirst().getCommitments();
                        shareData = secretI.getFirst().getSharedData();
                        int k = 0;
                        for (VerifiableShare verifiableShare : secretI) {
                            shares[k++] = verifiableShare.getShare();
                        }
                        secrets[i] = new OpenPublishedShares(shares, commitments, shareData);
                    }
                }
                ExtractedResponse extractedResponse = new ExtractedResponse(plainData, null);
                TOMMessage lastMsg = tomMessages[lastReceived];
                return new TOMMessage(lastMsg.getSender(),
                        lastMsg.getSession(), lastMsg.getSequence(),
                        lastMsg.getOperationId(), extractedResponse.serialize(), new byte[0],
                        lastMsg.getViewID(), lastMsg.getReqType());
            }
        }
        logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
        return null;
    }
}
