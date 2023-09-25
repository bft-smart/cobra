package confidential.client;

import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.util.Extractor;
import bftsmart.tom.util.HashedExtractor;
import bftsmart.tom.util.ServiceContent;
import bftsmart.tom.util.ServiceResponse;
import confidential.ConfidentialMessage;
import confidential.ExtractedResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.commitment.Commitment;
import vss.commitment.CommitmentScheme;
import vss.commitment.CommitmentUtils;
import vss.facade.Mode;
import vss.facade.SecretSharingException;
import vss.secretsharing.OpenPublishedShares;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.*;

/**
 * @author Robin
 */
public abstract class ServersResponseHandler implements Comparator<ServiceContent>, Extractor, HashedExtractor {
	protected final Logger logger = LoggerFactory.getLogger("confidential");
	protected CommitmentScheme commitmentScheme;
	protected ClientConfidentialityScheme confidentialityScheme;
	private final Map<ServiceContent, ConfidentialMessage> responses;
	private final Map<ConfidentialMessage, Integer> responseHashes;

	public ServersResponseHandler() {
		this.responses = new HashMap<>();
		this.responseHashes = new HashMap<>();
	}

	public void setClientConfidentialityScheme(ClientConfidentialityScheme confidentialityScheme) {
		this.confidentialityScheme = confidentialityScheme;
		this.commitmentScheme = confidentialityScheme.getCommitmentScheme();
	}

	@Override
	public ServiceResponse extractResponse(TOMMessage[] replies, int sameContent, int lastReceived) {
		LinkedList<ConfidentialMessage> correctReplies = getCorrectReplies(replies, sameContent);

		if (correctReplies == null) {
			logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
			return null;
		}

		byte[] plainData = correctReplies.getFirst().getPlainData();
		byte[][] confidentialData = null;

		if (correctReplies.getFirst().getShares() != null) { // this response has secret data
			try {
				confidentialData = reconstructConfidentialData(correctReplies);
			} catch (SecretSharingException e) {
				return new ExtractedResponse(plainData, confidentialData, e);
			}
		}
		return new ExtractedResponse(plainData, confidentialData);
	}

	@Override
	public ServiceResponse extractHashedResponse(TOMMessage[] replies, TOMMessage fullReply, byte[] fullReplyHash,
												 int sameContent) {
		LinkedList<TOMMessage> correctReplies = getCorrectHashedReplies(replies, fullReply, fullReplyHash, sameContent);
		if (correctReplies == null) {
			logger.error("This should not happen. Did not found {} equivalent responses", sameContent);
			return null;
		}
		ConfidentialMessage fullConfidentialReply = reconstructConfidentialMessage(fullReply.getContent());
		if (fullConfidentialReply == null) {
			logger.error("This should not happen. Couldn't deserialized response from full reply sender {}",
					fullReply.getSender());
			return null;
		}

		byte[] plainData = fullConfidentialReply.getPlainData();
		VerifiableShare[] shares = fullConfidentialReply.getShares();

		if (shares == null) {
			return new ExtractedResponse(plainData, null);
		}

		BigInteger[] shareholders = new BigInteger[shares.length];
		byte[][] sharedData = new byte[shares.length][];
		for (int i = 0; i < shares.length; i++) {
			shareholders[i] = shares[i].getShare().getShareholder();
			sharedData[i] = shares[i].getSharedData();
		}

		LinkedList<ConfidentialMessage> correctConfidentialReplies = new LinkedList<>();
		correctConfidentialReplies.add(fullConfidentialReply);
		for (TOMMessage correctReply : correctReplies) {
			ConfidentialMessage correctConfidentialReply = reconstructHashedConfidentialMessage(
					fullReply.getReplicaSpecificContent(), shareholders, sharedData);
			if (correctConfidentialReply == null) {
				logger.error("This should not happen. Couldn't deserialized hashed response from {}",
						correctReply.getSender());
				return null;
			}
			correctConfidentialReplies.add(correctConfidentialReply);
		}

		byte[][] confidentialData = null;
		try {
			confidentialData = reconstructConfidentialData(correctConfidentialReplies);
		} catch (SecretSharingException e) {
			return new ExtractedResponse(plainData, confidentialData, e);
		}

		return new ExtractedResponse(plainData, confidentialData);
	}


	protected byte[][] reconstructConfidentialData(LinkedList<ConfidentialMessage> correctReplies) throws SecretSharingException {
		OpenPublishedShares[] secretShares = reconstructOpenPublishedShares(correctReplies);
		byte[][] confidentialData = new byte[secretShares.length][];
		for (int i = 0; i < secretShares.length; i++) {
			confidentialData[i] = confidentialityScheme.combine(secretShares[i],
					secretShares[i].getSharedData() == null ? Mode.SMALL_SECRET : Mode.LARGE_SECRET);
		}
		return confidentialData;
	}

	protected OpenPublishedShares[] reconstructOpenPublishedShares(LinkedList<ConfidentialMessage> correctReplies) {
		ConfidentialMessage firstMsg = correctReplies.getFirst();
		int numSecrets = firstMsg.getShares().length;
		ArrayList<LinkedList<VerifiableShare>> verifiableShares =
				new ArrayList<>(numSecrets);
		for (int i = 0; i < numSecrets; i++) {
			verifiableShares.add(new LinkedList<>());
		}
		OpenPublishedShares[] confidentialData = new OpenPublishedShares[numSecrets];

		for (ConfidentialMessage confidentialMessage : correctReplies) {
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
			confidentialData[i] = secret;
		}
		return confidentialData;
	}

	@Override
	public int compare(ServiceContent o1, ServiceContent o2) {
		if (o1 == null && o2 == null)
			return 0;
		ConfidentialMessage response1 = responses.computeIfAbsent(o1, this::reconstructConfidentialMessage);
		ConfidentialMessage response2 = responses.computeIfAbsent(o2, this::reconstructConfidentialMessage);
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

	protected LinkedList<ConfidentialMessage> getCorrectReplies(TOMMessage[] replies, int sameContent) {
		ConfidentialMessage response;
		Map<Integer, LinkedList<ConfidentialMessage>> repliesSets = new HashMap<>();
		for (TOMMessage msg : replies) {
			if (msg == null)
				continue;
			response = responses.get(msg.getContent());
			if (response == null) {
				response = reconstructConfidentialMessage(msg.getContent());
			}
			Integer responseHash = responseHashes.get(response);
			if (responseHash == null) {
				responseHash = computeSameSecretHash(response);
			}
			LinkedList<ConfidentialMessage> msgList = repliesSets.computeIfAbsent(responseHash, k -> new LinkedList<>());
			msgList.add(response);
		}
		for (LinkedList<ConfidentialMessage> value : repliesSets.values()) {
			if (value.size() >= sameContent)
				return value;
		}
		return null;
	}

	protected LinkedList<TOMMessage> getCorrectHashedReplies(TOMMessage[] replies, TOMMessage fullReply,
															 byte[] fullReplyHash, int sameContent) {
		LinkedList<TOMMessage> repliesSets = new LinkedList<>();
		for (TOMMessage msg : replies) {
			if (msg == null)
				continue;
			if (msg == fullReply) {
				repliesSets.addFirst(msg);
			} else if (Arrays.equals(fullReplyHash, msg.getCommonContent())) {
				repliesSets.add(msg);
			}
		}
		if (repliesSets.size() >= sameContent)
			return repliesSets;
		return null;
	}

	protected ConfidentialMessage reconstructConfidentialMessage(ServiceContent response) {
		byte[] plainData = null;
		byte[][] sharedData = null;
		BigInteger[] shareholders = null;
		Commitment[] commitments = null;
		Share[] shares = null;
		try (ByteArrayInputStream bis = new ByteArrayInputStream(response.getCommonContent());
			 ObjectInput in = new ObjectInputStream(bis)) {
			int len = in.readInt();
			if (len != -1) {
				plainData = new byte[len];
				in.readFully(plainData);
			}
			int nConfidentialData = in.readInt();
			if (nConfidentialData != -1) {
				sharedData = new byte[nConfidentialData][];
				shareholders = new BigInteger[nConfidentialData];
				for (int i = 0; i < nConfidentialData; i++) {
					len = in.readInt();
					if (len != -1) {
						sharedData[i] = new byte[len];
						in.readFully(sharedData[i]);
					}

					byte[] b = new byte[in.readInt()];
					in.readFully(b);
					shareholders[i] = new BigInteger(b);
					in.readInt();// commitment hash
				}
			}
		} catch (IOException e) {
			logger.error("Error while deserializing common content");
			return null;
		}

		try (ByteArrayInputStream bis = new ByteArrayInputStream(response.getReplicaSpecificContent());
			 ObjectInput in = new ObjectInputStream(bis)) {
			int nConfidentialData = in.readInt();
			if (nConfidentialData != -1 && shareholders != null) {
				commitments = new Commitment[nConfidentialData];
				shares = new Share[nConfidentialData];
				for (int i = 0; i < nConfidentialData; i++) {
					int len = in.readInt();
					if (len != -1) {
						byte[] serializedShare = new byte[len];
						in.readFully(serializedShare);
						shares[i] = reconstructShare(shareholders[i], serializedShare);
					}
					commitments[i] = CommitmentUtils.getInstance().readCommitment(in);
				}
			}
		} catch (IOException | ClassNotFoundException e) {
			logger.error("Error while deserializing replica specific content");
			return null;
		}

		VerifiableShare[] verifiableShares = null;

		if (sharedData != null && commitments != null) {
			verifiableShares = new VerifiableShare[sharedData.length];
			for (int i = 0; i < sharedData.length; i++) {
				byte[] sharedDatum = sharedData[i];
				Commitment commitment = commitments[i];
				verifiableShares[i] = new VerifiableShare(shares[i], commitment, sharedDatum);
			}
		}
		return new ConfidentialMessage(plainData, verifiableShares);
	}

	protected ConfidentialMessage reconstructHashedConfidentialMessage(byte[] replicaSpecificContent,
																	   BigInteger[] shareholders,
																	   byte[][] sharedData) {
		Commitment[] commitments = null;
		Share[] shares = null;

		try (ByteArrayInputStream bis = new ByteArrayInputStream(replicaSpecificContent);
			 ObjectInput in = new ObjectInputStream(bis)) {
			int nConfidentialData = in.readInt();
			if (nConfidentialData != -1 && shareholders != null) {
				commitments = new Commitment[nConfidentialData];
				shares = new Share[nConfidentialData];
				for (int i = 0; i < nConfidentialData; i++) {
					int len = in.readInt();
					if (len != -1) {
						byte[] serializedShare = new byte[len];
						in.readFully(serializedShare);
						shares[i] = reconstructShare(shareholders[i], serializedShare);
					}
					commitments[i] = CommitmentUtils.getInstance().readCommitment(in);
				}
			}
		} catch (IOException | ClassNotFoundException e) {
			logger.error("Error while deserializing replica specific content");
			return null;
		}

		VerifiableShare[] verifiableShares = null;

		if (sharedData != null && commitments != null) {
			verifiableShares = new VerifiableShare[sharedData.length];
			for (int i = 0; i < sharedData.length; i++) {
				byte[] sharedDatum = sharedData[i];
				Commitment commitment = commitments[i];
				verifiableShares[i] = new VerifiableShare(shares[i], commitment, sharedDatum);
			}
		}
		return new ConfidentialMessage(null, verifiableShares);
	}

	protected abstract Share reconstructShare(BigInteger shareholder, byte[] serializedShare);

	protected int computeSameSecretHash(ConfidentialMessage message) {
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

	public void reset() {
		responses.clear();
		responseHashes.clear();
	}
}
