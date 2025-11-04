package confidential.benchmark;

import bftsmart.tom.MessageContext;
import confidential.ConfidentialMessage;
import confidential.facade.server.ConfidentialServerFacade;
import confidential.facade.server.ConfidentialSingleExecutable;
import confidential.statemanagement.ConfidentialSnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.secretsharing.VerifiableShare;

import java.io.*;
import java.util.HashSet;
import java.util.Set;

public class ThroughputLatencyKVStoreServer implements ConfidentialSingleExecutable {
    private final Logger logger = LoggerFactory.getLogger("demo");
	private final Logger measurementLogger = LoggerFactory.getLogger("measurement");
	private byte[] plainResponse;
	private VerifiableShare privateResponse;
    private long startTime;
    private long numRequests;
    private final Set<Integer> senders;

	public static void main(String[] args) throws NumberFormatException {
        if (args.length != 1) {
            System.out.println("USAGE: confidential.benchmark.ThroughputLatencyKVStoreServer <server id>");
            System.exit(-1);
        }
		int processId = Integer.parseInt(args[0]);
        new ThroughputLatencyKVStoreServer(processId);
    }

    ThroughputLatencyKVStoreServer(int processId) {
		senders = new HashSet<>(1000);
        new ConfidentialServerFacade(processId, this);
    }

    @Override
    public ConfidentialMessage appExecuteOrdered(byte[] plainData, VerifiableShare[] shares, MessageContext msgCtx) {
        numRequests++;
        senders.add(msgCtx.getSender());
		try {
			boolean isResponse = plainData.length > 0 && plainData[0] == 1;
			if (isResponse && plainResponse == null && privateResponse == null) {
				if (plainData.length > 1) {
					plainResponse = new byte[plainData.length - 1];
					System.arraycopy(plainData, 1, plainResponse, 0, plainResponse.length);
				}
				if (shares != null && shares.length > 0) {
					privateResponse = shares[0];
				}
			}

			if (privateResponse != null) {
				return new ConfidentialMessage(plainResponse, privateResponse);
			}

			if (plainResponse != null) {
				return new ConfidentialMessage(plainResponse);
			}
			return new ConfidentialMessage();
		} finally {
			printMeasurement();
		}
    }

    private void printMeasurement() {
        long currentTime = System.nanoTime();
		long delta = currentTime - startTime;
		if (delta >= 2_000_000_000) {
			measurementLogger.info("M-clients: {}", senders.size());
			measurementLogger.info("M-delta: {}", delta);
			measurementLogger.info("M-requests: {}", numRequests);

            numRequests = 0;
            startTime = currentTime;
            senders.clear();
        }
    }

    @Override
    public ConfidentialMessage appExecuteUnordered(byte[] plainData, VerifiableShare[] shares, MessageContext msgCtx) {
        numRequests++;
        senders.add(msgCtx.getSender());

		try {
			if (privateResponse != null) {
				return new ConfidentialMessage(plainResponse, privateResponse);
			}

			if (plainResponse != null) {
				return new ConfidentialMessage(plainResponse);
			}
			return new ConfidentialMessage();
		} finally {
			printMeasurement();
		}
    }

    @Override
    public ConfidentialSnapshot getConfidentialSnapshot() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
			out.writeInt(plainResponse == null ? -1 : plainResponse.length);
			if (plainResponse != null) {
				out.write(plainResponse);
			}
            out.flush();
            bos.flush();
			if (privateResponse == null) {
				return new ConfidentialSnapshot(bos.toByteArray());
			}
            return new ConfidentialSnapshot(bos.toByteArray(), privateResponse);
        } catch (IOException e) {
            logger.error("Error while creating snapshot", e);
        }
        return null;
    }

    @Override
    public void installConfidentialSnapshot(ConfidentialSnapshot snapshot) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(snapshot.getPlainData());
             ObjectInput in = new ObjectInputStream(bis)) {
			int responseSize = in.readInt();
			if (responseSize != -1) {
				plainResponse = new byte[responseSize];
				in.readFully(plainResponse);
			}
			VerifiableShare[] shares = snapshot.getShares();
			if (shares != null && shares.length > 0) {
				privateResponse = shares[0];
			}
		} catch (IOException e) {
            logger.error("Error while installing snapshot", e);
        }
    }
}
