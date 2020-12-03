package confidential.demo.statechecker;

import bftsmart.tom.MessageContext;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.demo.map.client.Operation;
import confidential.facade.server.ConfidentialServerFacade;
import confidential.facade.server.ConfidentialSingleExecutable;
import confidential.statemanagement.ConfidentialSnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Map;
import java.util.TreeMap;


public class Server implements ConfidentialSingleExecutable {

    public static void main(String[] args) {
        int processId = Integer.parseInt(args[0]);
        new Server(processId);
    }

    private final Logger logger = LoggerFactory.getLogger("demo");
    private Map<String, ConfidentialData> map;

    public Server(int processId) {
        map = new TreeMap<>();
        new ConfidentialServerFacade(processId, this);
    }

    @Override
    public ConfidentialMessage appExecuteOrdered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(plainData);
             ObjectInput in = new ObjectInputStream(bis)) {
            Operation op = Operation.getOperation(in.read());
            String str;
            ConfidentialData value;
            switch (op) {
                case GET:
                    str = in.readUTF();
                    value = map.get(str);
                    if (value != null)
                        return new ConfidentialMessage(null, value);
                    else
                        return new ConfidentialMessage();
                case PUT:
                    str = in.readUTF();
                    value = map.put(str, shares[0]);
                    if (value != null)
                        return new ConfidentialMessage(null, value);
                    else
                        return new ConfidentialMessage();
            }
        } catch (IOException e) {
            logger.error("Failed to attend ordered request from {}", msgCtx.getSender(), e);
        }
        return null;
    }

    @Override
    public ConfidentialMessage appExecuteUnordered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(plainData);
             ObjectInput in = new ObjectInputStream(bis)) {
            Operation op = Operation.getOperation(in.read());
            String str;
            ConfidentialData value;
            if (op == Operation.GET) {
                str = in.readUTF();
                value = map.get(str);
                if (value != null)
                    return new ConfidentialMessage(null, value);
                else
                    return new ConfidentialMessage();
            }
        } catch (IOException e) {
            logger.error("Failed to attend unordered request from {}", msgCtx.getSender(), e);
        }
        return null;
    }

    @Override
    public ConfidentialSnapshot getConfidentialSnapshot() {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeInt(map.size());
            ConfidentialData[] shares = new ConfidentialData[map.size()];
            int i = 0;
            for (Map.Entry<String, ConfidentialData> e : map.entrySet()) {
                out.writeUTF(e.getKey());
                shares[i++] = e.getValue();
            }
            out.flush();
            bos.flush();
            return new ConfidentialSnapshot(bos.toByteArray(), shares);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void installConfidentialSnapshot(ConfidentialSnapshot snapshot) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(snapshot.getPlainData());
             ObjectInput in = new ObjectInputStream(bis)) {
            int size = in.readInt();
            map = new TreeMap<>();
            ConfidentialData[] shares = snapshot.getShares();
            for (int i = 0; i < size; i++) {
                map.put(in.readUTF(), shares[i]);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
