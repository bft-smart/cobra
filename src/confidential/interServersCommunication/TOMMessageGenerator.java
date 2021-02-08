package confidential.interServersCommunication;

import bftsmart.reconfiguration.ServerViewController;
import bftsmart.tom.core.messages.TOMMessage;
import bftsmart.tom.core.messages.TOMMessageType;
import bftsmart.tom.util.TOMUtil;

import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

public class TOMMessageGenerator {
	private final int id;
	private final int session;
	private final AtomicInteger orderedSeq;
	private final AtomicInteger unorderedSeq;
	private final AtomicInteger requestId;
	private final ServerViewController controller;
	
	public TOMMessageGenerator(ServerViewController controller) {
		this.controller = controller;
		this.id = controller.getStaticConf().getProcessId();
		this.orderedSeq = new AtomicInteger(0);
		this.unorderedSeq = new AtomicInteger(0);
		this.requestId = new AtomicInteger(0);
		this.session = new Random(System.nanoTime()).nextInt();
	}
	
	public TOMMessage getNextOrdered(byte[] metadata, byte[] payload) {
		int os = orderedSeq.getAndIncrement();
		int reqId = requestId.getAndIncrement();
		return nextMessage(metadata, payload, os, reqId, TOMMessageType.ORDERED_REQUEST);
	}

	public TOMMessage getNextUnordered(byte[] payload) {
		int os = unorderedSeq.getAndIncrement();
		int reqId = requestId.getAndIncrement();
		return nextMessage(null, payload, os, reqId, TOMMessageType.UNORDERED_REQUEST);
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
				new byte[0],
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
