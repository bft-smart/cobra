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
package confidential.demo.ycsb;

import bftsmart.tom.MessageContext;
import confidential.ConfidentialData;
import confidential.ConfidentialMessage;
import confidential.facade.server.ConfidentialServerFacade;
import confidential.facade.server.ConfidentialSingleExecutable;
import confidential.statemanagement.ConfidentialSnapshot;

import java.io.*;
import java.util.TreeMap;

/**
 *
 * @author Marcel Santos
 *
 */
public class YCSBServer implements ConfidentialSingleExecutable {

    private static final boolean _debug = false;
    private TreeMap<String, YCSBTable> mTables;

    private boolean logPrinted = false;

    public static void main(String[] args) throws Exception {
        if (args.length == 1) {
            new YCSBServer(new Integer(args[0]));
        } else {
            System.out.println("Usage: java ... YCSBConfidentialServer <replica_id>");
        }
    }

    private YCSBServer(int id) {
        this.mTables = new TreeMap<>();
        new ConfidentialServerFacade(id, this);
    }

    @Override
    public ConfidentialMessage appExecuteOrdered(byte[] plainData, ConfidentialData[] shares, MessageContext msgCtx) {
        if (msgCtx != null && msgCtx.getConsensusId() % 1000 == 0 && !logPrinted) {
            System.out.println("YCSBConfidentialServer executing CID: " + msgCtx.getConsensusId());
            logPrinted = true;
        } else {
            logPrinted = false;
        }

        YCSBMessage aRequest = YCSBMessage.getObject(plainData);
        YCSBMessage reply = YCSBMessage.newErrorMessage("");
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
                            mTables.put(aRequest.getTable(), new YCSBTable());
                        }
                        if (!mTables.get(aRequest.getTable()).containsKey(aRequest.getKey())) {
                            mTables.get(aRequest.getTable()).put(aRequest.getKey(), aRequest.getValues());
                            reply = YCSBMessage.newInsertResponse(0);
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
                            mTables.put((String) aRequest.getTable(), new YCSBTable());
                        }
                        mTables.get(aRequest.getTable()).put(aRequest.getKey(), aRequest.getValues());
                        reply = YCSBMessage.newUpdateResponse(1);
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
        YCSBMessage aRequest = YCSBMessage.getObject(plainData);
        YCSBMessage reply = YCSBMessage.newErrorMessage("");
        if (aRequest == null) {
            return new ConfidentialMessage(reply.getBytes());
        }
        if (_debug) {
            System.out.println("[INFO] Processing an unordered request");
        }

        switch (aRequest.getType()) {
            case READ: { // ##### operation: read #####
                switch (aRequest.getEntity()) {
                    case RECORD: // ##### entity: record #####
                        if (!mTables.containsKey(aRequest.getTable())) {
                            reply = YCSBMessage.newErrorMessage("Table not found");
                            break;
                        }
                        if (!mTables.get(aRequest.getTable()).containsKey(aRequest.getKey())) {
                            reply = YCSBMessage.newErrorMessage("Record not found");
                            break;
                        } else {
                            reply = YCSBMessage.newReadResponse(mTables.get(aRequest.getTable()).get(aRequest.getKey()), 0);
                            break;
                        }
                }
            }
        }
        if (_debug) {
            System.out.println("[INFO] Sending reply");
        }
        return new ConfidentialMessage(reply.getBytes());
    }

    @Override
    public ConfidentialSnapshot getConfidentialSnapshot() {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutput out = new ObjectOutputStream(bos);
            out.writeObject(mTables);
            out.flush();
            bos.flush();
            out.close();
            bos.close();
            return new ConfidentialSnapshot(bos.toByteArray());
        } catch (IOException ioe) {
            System.err.println("[ERROR] Error serializing state: "
                    + ioe.getMessage());
            return new ConfidentialSnapshot("ERROR".getBytes());
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public void installConfidentialSnapshot(ConfidentialSnapshot snapshot) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(snapshot.getPlainData());
            ObjectInput in = new ObjectInputStream(bis);
            mTables = (TreeMap<String, YCSBTable>) in.readObject();
            in.close();
            bis.close();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("[ERROR] Error deserializing state: "
                    + e.getMessage());
        }
    }
}