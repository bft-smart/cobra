package confidential.benchmark;

import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import bftsmart.tom.server.defaultservices.DefaultRecoverable;
import confidential.demo.map.client.Operation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class SmartThroughputLatencyKVStoreServer extends DefaultRecoverable {
    private final Logger logger = LoggerFactory.getLogger("demo");
    private Map<String, byte[]> map;
    private long startTime;
    private long numRequests;
    private Set<Integer> senders;
    private double maxThroughput;

    public static void main(String[] args) throws NumberFormatException {
        new SmartThroughputLatencyKVStoreServer(Integer.parseInt(args[0]));
    }

    SmartThroughputLatencyKVStoreServer(int processId) {
        map = new TreeMap<>();
        new ServiceReplica(processId, this, this);
        senders = new HashSet<>(1000);
    }

    private void printMeasurement() {
        long currentTime = System.nanoTime();
        double deltaTime = (currentTime - startTime) / 1_000_000_000.0;
        if ((int) (deltaTime / 2) > 0) {
            long delta = currentTime - startTime;
            double throughput = numRequests / deltaTime;
            if (throughput > maxThroughput)
                maxThroughput = throughput;
            logger.info("M:(clients[#]|requests[#]|delta[ns]|throughput[ops/s], max[ops/s])>({}|{}|{}|{}|{})",
                    senders.size(), numRequests, delta, throughput, maxThroughput);
            numRequests = 0;
            startTime = currentTime;
            senders.clear();
        }
    }

    private byte[] execute(byte[] command, MessageContext msgCtx) {
        numRequests++;
        senders.add(msgCtx.getSender());
        try (ByteArrayInputStream bis = new ByteArrayInputStream(command);
             ObjectInput in = new ObjectInputStream(bis)) {
            Operation op = Operation.getOperation(in.read());
            String str;
            byte[] value;
            switch (op) {
                case GET:
                    str = in.readUTF();
                    value = map.get(str);
                    return value;
                case PUT:
                    str = in.readUTF();
                    value = new byte[in.readInt()];
                    in.readFully(value);
                    map.put(str, value);
                    return null;
            }
        } catch (IOException e) {
            logger.error("Failed to attend ordered request from {}", msgCtx.getSender(), e);
        } finally {
            printMeasurement();
        }
        return null;
    }

    @Override
    public void installSnapshot(byte[] state) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(state);
             ObjectInput in = new ObjectInputStream(bis)) {
            int size = in.readInt();
            map = new TreeMap<>();
            senders = new HashSet<>(1000);
            for (int i = 0; i < size; i++) {
                String key = in.readUTF();
                byte[] b = new byte[in.readInt()];
                in.readFully(b);
                map.put(key, b);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public byte[] getSnapshot() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeInt(map.size());
            for (Map.Entry<String, byte[]> e : map.entrySet()) {
                out.writeUTF(e.getKey());
                out.writeInt(e.getValue().length);
                out.write(e.getValue());
            }
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public byte[][] appExecuteBatch(byte[][] commands, MessageContext[] msgCtxs, boolean fromConsensus) {
        byte[][] replies = new byte[commands.length][];

        for (int i = 0; i < commands.length; i++) {
            replies[i] = execute(commands[i], msgCtxs[i]);
        }

        return replies;
    }

    @Override
    public byte[] appExecuteUnordered(byte[] command, MessageContext msgCtx) {
        return execute(command, msgCtx);
    }
}
