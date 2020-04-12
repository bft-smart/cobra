/**
 * Copyright (c) 2007-2013 Alysson Bessani, Eduardo Alchieri, Paulo Sousa, and the authors indicated in the @author tags
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package confidential.demo.ycsb.confidential;

import bftsmart.tom.MessageContext;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.facade.server.ConfidentialServerFacade;
import confidential.facade.server.ConfidentialSingleExecutable;
import confidential.statemanagement.ConfidentialSnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;

/**
 *
 * @author Marcel Santos
 *
 */
public class YCSBConfidentialServer implements ConfidentialSingleExecutable {
    private Logger logger = LoggerFactory.getLogger("demo");
    private static final boolean _debug = false;
    private TreeMap<String, YCSBConfidentialTable> mTables;
    private long startTime;
    private long numRequests;
    private boolean logPrinted = false;
    private int id;

    public static void main(String[] args) {
        if (args.length == 1) {
            new YCSBConfidentialServer(new Integer(args[0]));
        } else {
            System.out.println("Usage: java ... YCSBConfidentialServer <replica_id>");
        }
    }

    private YCSBConfidentialServer(int id) {
        this.mTables = new TreeMap<>();
        new ConfidentialServerFacade(id, this);
        startTime = System.nanoTime();
        this.id = id;
    }

    @Override
    public ConfidentialMessage appExecuteOrdered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
        /*if (msgCtx != null && msgCtx.getConsensusId() % 1000 == 0 && !logPrinted) {
            logger.info("YCSBConfidentialServer executing CID: " + msgCtx.getConsensusId());
            logPrinted = true;
        } else {
            logPrinted = false;
        }*/
        //if (id == 0) {
            long currentTime = System.nanoTime();
            double deltaTime = (currentTime - startTime) / 1_000_000_000;

            if ((int) (deltaTime / 5) > 0) {
                double throughput = numRequests / deltaTime;
                logger.info("Requests: {} | DeltaTime[s]: {} | Throughput[ops/s]: {}", numRequests, deltaTime, throughput);
                numRequests = 0;
                startTime = currentTime;
            }

            numRequests++;
        //}
        YCSBConfidentialMessage aRequest = YCSBConfidentialMessage.getObject(plainData);
        YCSBConfidentialMessage reply = YCSBConfidentialMessage.newErrorMessage("");
        if (aRequest == null) {
            return new ConfidentialMessage(reply.getBytes());
        }
        if (_debug) {
            System.out.println("[INFO] Processing an ordered request");
        }
        switch (aRequest.getType()) {
            case CREATE: { // ##### operation: create #####
                switch (aRequest.getEntity()) {
                    case RECORD: // ##### entity: record #####
                        if (!mTables.containsKey(aRequest.getTable())) {
                            mTables.put(aRequest.getTable(), new YCSBConfidentialTable());
                        }
                        if (!mTables.get(aRequest.getTable()).containsKey(aRequest.getKey())) {
                            String[] values = aRequest.getValues();
                            if (values.length != shares.length) {
                                reply = YCSBConfidentialMessage.newErrorMessage("values.length != shares.length");
                                break;
                            }
                            HashMap<String, ConfidentialData> map = new HashMap<>(values.length);
                            for (int i = 0; i < values.length; i++) {
                                map.put(values[i], shares[i]);
                            }
                            mTables.get(aRequest.getTable()).put(aRequest.getKey(), map);
                            reply = YCSBConfidentialMessage.newInsertResponse(0);
                        }
                        break;
                    default: // Only create records
                        break;
                }
                break;
            }

            case UPDATE: { // ##### operation: update #####
                switch (aRequest.getEntity()) {
                    case RECORD: // ##### entity: record #####
                        if (!mTables.containsKey(aRequest.getTable())) {
                            mTables.put(aRequest.getTable(), new YCSBConfidentialTable());
                        }
                        String[] values = aRequest.getValues();
                        if (values.length != shares.length) {
                            reply = YCSBConfidentialMessage.newErrorMessage("values.length != shares.length");
                            break;
                        }
                        HashMap<String, ConfidentialData> map = new HashMap<>(values.length);
                        for (int i = 0; i < values.length; i++) {
                            map.put(values[i], shares[i]);
                        }
                        mTables.get(aRequest.getTable()).put(aRequest.getKey(), map);
                        reply = YCSBConfidentialMessage.newUpdateResponse(1);
                        break;
                    default: // Only update records
                        break;
                }
                break;
            }
        }
        if (_debug) {
            System.out.println("[INFO] Sending reply");
        }
        return new ConfidentialMessage(reply.getBytes());
    }

    @Override
    public ConfidentialMessage appExecuteUnordered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
        YCSBConfidentialMessage aRequest = YCSBConfidentialMessage.getObject(plainData);
        YCSBConfidentialMessage reply = YCSBConfidentialMessage.newErrorMessage("");
        if (aRequest == null) {
            return new ConfidentialMessage(reply.getBytes());
        }
        if (_debug) {
            System.out.println("[INFO] Processing an unordered request");
        }
        ConfidentialData[] sharesResponse = null;
        switch (aRequest.getType()) {
            case READ: { // ##### operation: read #####
                switch (aRequest.getEntity()) {
                    case RECORD: // ##### entity: record #####
                        if (!mTables.containsKey(aRequest.getTable())) {
                            reply = YCSBConfidentialMessage.newErrorMessage("Table not found");
                            break;
                        }
                        if (!mTables.get(aRequest.getTable()).containsKey(aRequest.getKey())) {
                            reply = YCSBConfidentialMessage.newErrorMessage("Record not found");
                            break;
                        } else {
                            Map<String, ConfidentialData> response = mTables.get(aRequest.getTable()).get(aRequest.getKey());
                            String[] keys = new String[response.size()];
                            sharesResponse = new ConfidentialData[response.size()];
                            int k = 0;
                            for (Map.Entry<String, ConfidentialData> entry : response.entrySet()) {
                                keys[k] = entry.getKey();
                                sharesResponse[k] = entry.getValue();
                                k++;
                            }
                            reply = YCSBConfidentialMessage.newReadResponse(keys, 0);
                            break;
                        }
                }
            }
        }
        if (_debug) {
            System.out.println("[INFO] Sending reply");
        }

        return sharesResponse == null ? new ConfidentialMessage(reply.getBytes())
                : new ConfidentialMessage(reply.getBytes(), sharesResponse);
    }

    @Override
    public ConfidentialSnapshot getConfidentialSnapshot() {

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            List<ConfidentialData> shares = new LinkedList<>();

            out.writeInt(mTables.size());
            for (Map.Entry<String, YCSBConfidentialTable> table : mTables.entrySet()) {
                out.writeUTF(table.getKey());
                out.writeInt(table.getValue().size());
                for (Map.Entry<String, HashMap<String, ConfidentialData>> key : table.getValue().entrySet()) {
                    out.writeUTF(key.getKey());
                    out.writeInt(key.getValue().size());
                    for (Map.Entry<String, ConfidentialData> field : key.getValue().entrySet()) {
                        out.writeUTF(field.getKey());
                        shares.add(field.getValue());
                    }
                }
            }
            out.flush();
            bos.flush();
            ConfidentialData[] allShares = new ConfidentialData[shares.size()];
            int i = 0;
            for (ConfidentialData share : shares) {
                allShares[i++] = share;
            }
            return new ConfidentialSnapshot(bos.toByteArray(), allShares);
        } catch (IOException e) {
            logger.error("Error serializing state: {}", e.getMessage());
            return new ConfidentialSnapshot("ERROR".getBytes());
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public void installConfidentialSnapshot(ConfidentialSnapshot snapshot) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(snapshot.getPlainData());
             ObjectInput in = new ObjectInputStream(bis)) {
            ConfidentialData[] shares = snapshot.getShares();
            int i = 0;
            int nTables = in.readInt();
            mTables = new TreeMap<>();
            while (nTables-- > 0) {
                String tableName = in.readUTF();
                YCSBConfidentialTable table = new YCSBConfidentialTable();
                int nKeys = in.readInt();
                while (nKeys-- > 0) {
                    String key = in.readUTF();
                    int nFields = in.readInt();
                    HashMap<String, ConfidentialData> fields = new HashMap<>(nFields);
                    while (nFields-- > 0) {
                        String field = in.readUTF();
                        fields.put(field, shares[i]);
                        i++;
                    }
                    table.put(key, fields);
                }
                mTables.put(tableName, table);
            }
        } catch (IOException e) {
            logger.error("[ERROR] Error deserializing state: {}", e.getMessage());
        }
    }
}