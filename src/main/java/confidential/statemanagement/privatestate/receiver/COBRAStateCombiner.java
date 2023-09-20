package confidential.statemanagement.privatestate.receiver;

import bftsmart.consensus.messages.ConsensusMessage;
import bftsmart.tom.MessageContext;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.server.defaultservices.CommandsInfo;
import bftsmart.tom.server.defaultservices.DefaultApplicationState;
import bftsmart.tom.util.TOMUtil;
import confidential.server.Request;
import confidential.statemanagement.ConfidentialSnapshot;
import confidential.statemanagement.ReconstructionCompleted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;

/**
 * @author robin
 */
public class COBRAStateCombiner extends Thread {
	private final Logger logger = LoggerFactory.getLogger("state_transfer");
	private final int pid;
	private final byte[] commonState;
	private final LinkedList<VerifiableShare> shares;
	private final ReconstructionCompleted reconstructionListener;

	public COBRAStateCombiner(int pid, byte[] commonState, LinkedList<VerifiableShare> shares,
							  ReconstructionCompleted reconstructionListener) {
		this.pid = pid;
		this.commonState = commonState;
		this.shares = shares;
		this.reconstructionListener = reconstructionListener;
	}

	@Override
	public void run() {
		try (ObjectInputStream commonStateStream = new ObjectInputStream(new ByteArrayInputStream(commonState))) {
			logger.debug("Combining states");
			long startTime = System.nanoTime();
			DefaultApplicationState reconstructedState = reconstructState(commonStateStream);
			long endTime = System.nanoTime();
			if (reconstructedState == null) {
				logger.error("Reconstructed state is null. Waiting for more blinded shares.");
				return;
			}
			double totalTime = (endTime - startTime) / 1_000_000.0;
			logger.info("Took {} ms to combine states", totalTime);
			reconstructionListener.onReconstructionCompleted(reconstructedState);
		} catch (IOException | ClassNotFoundException e) {
			logger.error("Failed to combine states.", e);
		}
	}

	private DefaultApplicationState reconstructState(ObjectInputStream commonStateStream) throws IOException, ClassNotFoundException {
		int lastCheckPointCID = commonStateStream.readInt();
		int lastCID = commonStateStream.readInt();
		int logSize = commonStateStream.readInt();

		Iterator<VerifiableShare> reconstructedShares = shares.iterator();
		CommandsInfo[] reconstructedLog = null;
		if (logSize != -1)  {
			reconstructedLog = reconstructLog(commonStateStream, logSize, reconstructedShares);
			if (reconstructedLog == null) {
				logger.error("Failed to reconstruct log");
				return null;
			}
		}

		boolean hasState = commonStateStream.readBoolean();
		ConfidentialSnapshot reconstructedSnapshot = null;
		if (hasState) {
			reconstructedSnapshot = reconstructSnapshot(commonStateStream, reconstructedShares);
		}

		byte[] reconstructedSerializedState = reconstructedSnapshot == null ? null : reconstructedSnapshot.serialize();

		return new DefaultApplicationState(
				reconstructedLog,
				lastCheckPointCID,
				lastCID,
				reconstructedSerializedState,
				reconstructedSerializedState == null ? null : TOMUtil.computeHash(reconstructedSerializedState),
				pid
		);
	}

	private ConfidentialSnapshot reconstructSnapshot(ObjectInputStream commonStateStream, Iterator<VerifiableShare> reconstructedShares) throws IOException {
		logger.debug("Reconstructing snapshot");
		int plainDataSize = commonStateStream.readInt();
		byte[] plainData = null;
		if (plainDataSize > -1) {
			plainData = new byte[plainDataSize];
			commonStateStream.readFully(plainData);
		}

		int nShares = commonStateStream.readInt();
		VerifiableShare[] snapshotShares = null;
		if (nShares > -1) {
			snapshotShares = getRefreshedShares(commonStateStream, nShares, reconstructedShares);
		}

		return snapshotShares == null ?
				new ConfidentialSnapshot(plainData)
				: new ConfidentialSnapshot(plainData, snapshotShares);
	}

	private CommandsInfo[] reconstructLog(ObjectInputStream commonStateStream, int logSize, Iterator<VerifiableShare> reconstructedShares) throws IOException {
		logger.debug("Reconstructing log");
		CommandsInfo[] log = new CommandsInfo[logSize];
		for (int i = 0; i < logSize; i++) {
			MessageContext[] msgCtx = deserializeMessageContext(commonStateStream);
			int nCommands = commonStateStream.readInt();
			byte[][] commands = new byte[nCommands][];
			for (int j = 0; j < nCommands; j++) {
				int nShares = commonStateStream.readInt();
				byte[] command;
				if (nShares == -1) {
					command = new byte[commonStateStream.readInt()];
					commonStateStream.readFully(command);
				} else {
					VerifiableShare[] shares = getRefreshedShares(commonStateStream, nShares, reconstructedShares);

					byte[] b = new byte[commonStateStream.readInt()];
					commonStateStream.readFully(b);
					Request request = Request.deserialize(b);
					if (request == null) {
						logger.error("Failed to deserialize request");
						return null;
					}
					request.setShares(shares);
					command = request.serialize();
					if (command == null) {
						logger.error("Failed to serialize request");
						return null;
					}
				}
				commands[j] = command;
			}
			log[i] = new CommandsInfo(commands, msgCtx);
		}
		return log;
	}

	private VerifiableShare[] getRefreshedShares(ObjectInputStream commonStateStream, int nShares, Iterator<VerifiableShare> reconstructedShares)
			throws IOException {
		VerifiableShare[] shares = new VerifiableShare[nShares];
		for (int i = 0; i < nShares; i++) {
			int shareDataSize = commonStateStream.readInt();
			byte[] sharedData = null;
			if (shareDataSize > -1) {
				sharedData = new byte[shareDataSize];
				commonStateStream.readFully(sharedData);
			}
			VerifiableShare vs = reconstructedShares.next();
			reconstructedShares.remove();
			vs.setSharedData(sharedData);
			shares[i] = vs;
		}
		return shares;
	}

	private MessageContext[] deserializeMessageContext(ObjectInput in) throws IOException {
		int size = in.readInt();
		if (size == -1)
			return null;
		MessageContext[] messageContexts = new MessageContext[size];
		for (int i = 0; i < size; i++) {
			int sender = in.readInt();
			int viewId = in.readInt();
			TOMMessageType type = TOMMessageType.getMessageType(in.read());
			int session = in.readInt();
			int sequence = in.readInt();
			int operationId = in.readInt();
			int replyServer = in.readInt();
			int len = in.readInt();
			byte[] signature = null;
			if (len != -1) {
				signature = new byte[len];
				in.readFully(signature);
			}
			long timestamp = in.readLong();
			int regency = in.readInt();
			int leader = in.readInt();
			int consensusId = in.readInt();
			int numOfNonces = in.readInt();
			long seed = in.readLong();
			boolean hasReplicaSpecificContent = in.readBoolean();
			byte metadata = (byte) in.read();
			len = in.readInt();
			Set<ConsensusMessage> proof = null;
			if (len != -1) {
				proof = new HashSet<>(len);
				while (len-- > 0) {
					int from = -1;//in.readInt();
					int number = in.readInt();
					int epoch = in.readInt();
					int paxosType = in.readInt();
					int valueSize = in.readInt();
					byte[] value = null;
					if (valueSize != -1) {
						value = new byte[valueSize];
						in.readFully(value);
					}

					ConsensusMessage p = new ConsensusMessage(paxosType, number, epoch, from, value);
					proof.add(p);
				}
			}

			TOMMessage firstInBatch = new TOMMessage();
			//firstInBatch.rExternal(in);
			boolean lastInBatch = in.readBoolean();
			boolean noOp = in.readBoolean();
			//boolean readOnly = in.readBoolean();

			len = in.readInt();
			byte[] nonce;
			if (len != -1) {
				nonce = new byte[len];
				in.readFully(nonce);
			}

			MessageContext messageContext = new MessageContext(sender, viewId, type, session, sequence, operationId,
					replyServer, signature, timestamp, numOfNonces, seed, regency, leader, consensusId,
					proof, firstInBatch, noOp, hasReplicaSpecificContent, metadata);
			if (lastInBatch)
				messageContext.setLastInBatch();
			messageContexts[i] = messageContext;
		}

		return messageContexts;
	}
}
