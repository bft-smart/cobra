package confidential.client;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.Extractor;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.ExtractedResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitments;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

public class ConfidentialExtractor implements Extractor {
    private final Logger logger = LoggerFactory.getLogger("confidential");
    private Map<Integer, LinkedList<ConfidentialMessage>> responses;
    private Map<Integer, VerifiableShare> shares;

    public ConfidentialExtractor() {
        responses = new HashMap<>();
        shares = new HashMap<>();
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
                byte[] plainData = msgList.getFirst().getPlainData();
                ConfidentialMessage firstMsg = msgList.getFirst();
                OpenPublishedShares[] multipleOpenShares = null;
                if (firstMsg.getShares() != null) {
                    int numSecret = firstMsg.getShares().length;
                    VerifiableShare[][] verifiableShares = new VerifiableShare[numSecret][sameContent];
                    int i = 0;
                    for (ConfidentialMessage confidentialMessage : msgList) {
                        ConfidentialData[] shareI = confidentialMessage.getShares();
                        for (int j = 0; j < numSecret; j++) {
                            verifiableShares[j][i] = shareI[j];
                        }
                        i++;
                    }

                    multipleOpenShares = new OpenPublishedShares[numSecret];
                    Commitments commitments;
                    byte[] shareData;
                    Share[] shares;
                    for (int j = 0; j < numSecret; j++) {
                        shares = new Share[verifiableShares[j].length];
                        commitments = verifiableShares[j][0].getCommitments();
                        shareData = verifiableShares[j][0].getSharedData();
                        for (int k = 0; k < shares.length; k++)
                            shares[k] = verifiableShares[j][k].getShare();
                        multipleOpenShares[j] = new OpenPublishedShares(shares, commitments, shareData);
                    }
                }
                ExtractedResponse extractedResponse = new ExtractedResponse(plainData, multipleOpenShares);
                TOMMessage lastMsg = tomMessages[lastReceived];
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
