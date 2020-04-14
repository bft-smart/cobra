package confidential.interServersCommunication;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.util.TOMUtil;

import java.util.Random;

public class TOMMessageGenerator {
	private int id;
	private int session;
	private int orderedSeq;
	private int unorderedSeq;
	private int requestId;
	private ServerViewController controller;
	
	public TOMMessageGenerator(ServerViewController controller) {
		this.controller = controller;
		this.id = controller.getStaticConf().getProcessId();

		session = new Random(System.nanoTime()).nextInt();
	}
	
	public TOMMessage getNextOrdered(byte[] metadata, byte[] payload) {
		return nextMessage(metadata, payload, orderedSeq++, requestId++,
				TOMMessageType.ORDERED_REQUEST);
	}

	public TOMMessage getNextUnordered(byte[] payload) {
		return nextMessage(null, payload, unorderedSeq++, requestId++,
				TOMMessageType.UNORDERED_REQUEST);
	}

	private TOMMessage nextMessage(byte[] metadata, byte[] payload, int sequence,
								   int requestId, TOMMessageType type) {
		TOMMessage msg =  new TOMMessage(
				id,
				session,
				sequence,
				requestId,
				metadata,
				payload,
				controller.getCurrentViewId(),
				type);
		msg.serializedMessage = TOMMessage.messageToBytes(msg);
		if (controller.getStaticConf().getUseSignatures() == 1) {
			msg.serializedMessageSignature = TOMUtil.signMessage(controller.getStaticConf().getPrivateKey(), msg.serializedMessage);
			msg.signed = true;
		}
		return msg;

	}
}
