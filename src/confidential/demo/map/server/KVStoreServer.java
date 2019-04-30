package confidential.demo.map.server;

import bftsmart.tom.MessageContext;
import bftsmart.tom.ServiceReplica;
import confidential.ConfidentialMessage;
import confidential.server.ConfidentialRecoverable;
import confidential.demo.map.client.Operation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.util.Map;
import java.util.TreeMap;

public class KVStoreServer extends ConfidentialRecoverable {
    private Logger logger = LoggerFactory.getLogger("demo");
    private Map<String, VerifiableShare> map;

    public KVStoreServer(int processId) {
        super(processId);
        map = new TreeMap<>();
        new ServiceReplica(processId, this, this);
    }

    @Override
    public ConfidentialMessage appExecuteOrdered(byte[] plainData, VerifiableShare[] shares, MessageContext msgCtx) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(plainData);
             ObjectInput in = new ObjectInputStream(bis)) {
            Operation op = Operation.getOperation(in.read());
            String str;
            VerifiableShare value;
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
                case REMOVE:
                    str = in.readUTF();
                    value = map.remove(str);
                    if (value != null)
                        return new ConfidentialMessage(null, value);
                    else
                        return new ConfidentialMessage();
                case GET_ALL:
                    if (map.isEmpty())
                        return new ConfidentialMessage();
                    VerifiableShare[] allValues = new VerifiableShare[map.size()];
                    int i = 0;
                    for (VerifiableShare share : map.values())
                        allValues[i++] = share;
                    return new ConfidentialMessage(null, allValues);
            }
        } catch (IOException e) {
            logger.error("Failed to attend ordered request from {}", msgCtx.getSender(), e);
        }
        return null;
    }

    @Override
    public ConfidentialMessage appExecuteUnordered(byte[] plainData, VerifiableShare[] shares, MessageContext msgCtx) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(plainData);
             ObjectInput in = new ObjectInputStream(bis)) {
            Operation op = Operation.getOperation(in.read());
            String str;
            VerifiableShare value;
            switch (op) {
                case GET:
                    str = in.readUTF();
                    value = map.get(str);
                    if (value != null)
                        return new ConfidentialMessage(null, value);
                    else
                        return new ConfidentialMessage();
                case GET_ALL:
                    if (map.isEmpty())
                        return new ConfidentialMessage();
                    VerifiableShare[] allValues = (VerifiableShare[]) map.values().toArray();
                    return new ConfidentialMessage(null, allValues);
            }
        } catch (IOException e) {
            logger.error("Failed to attend unordered request from {}", msgCtx.getSender(), e);
        }
        return null;
    }
}
