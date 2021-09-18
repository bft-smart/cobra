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

import com.yahoo.ycsb.ByteIterator;
import com.yahoo.ycsb.DB;
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import vss.facade.SecretSharingException;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 *
 * @author Marcel Santos
 *
 */
public class YCSBConfidentialClient extends DB {
    private static AtomicInteger counter = new AtomicInteger();
    private ConfidentialServiceProxy proxy = null;
    private int myId;

    public YCSBConfidentialClient() {
    }

    @Override
    public void init() {
        Properties props = getProperties();
        int initId = Integer.valueOf((String) props.get("smart-initkey"));
        myId = initId + counter.addAndGet(1);
        try {
            proxy = new ConfidentialServiceProxy(myId);
        } catch (SecretSharingException e) {
            e.printStackTrace();
        }
        System.out.println("YCSBKVClient. Initiated client id: " + myId);
    }

    @Override
    public int delete(String arg0, String arg1) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int insert(String table, String key,
                      HashMap<String, ByteIterator> values) {
        try {
            Iterator<String> valueIt = values.keySet().iterator();

            String[] keys = new String[values.size()];
            byte[][] secrets = new byte[values.size()][];
            int i = 0;
            while (valueIt.hasNext()) {
                String field = valueIt.next();
                keys[i] = field;
                secrets[i] = values.get(field).toArray();
                i++;
            }
            YCSBConfidentialMessage msg = YCSBConfidentialMessage.newInsertRequest(table, key, keys);
            Response reply = proxy.invokeOrdered(msg.getBytes(), secrets);
            YCSBConfidentialMessage replyMsg = YCSBConfidentialMessage.getObject(reply.getPainData());
            return replyMsg.getResult();
        } catch (SecretSharingException e) {
            e.printStackTrace();
        }
        return -1;
    }

    @Override
    public int read(String table, String key,
                    Set<String> fields, HashMap<String, ByteIterator> result) {
        try {
            //HashMap<String, ConfidentialData> results = new HashMap<>();
            YCSBConfidentialMessage request = YCSBConfidentialMessage.newReadRequest(table, key, fields, null);
            Response reply = proxy.invokeUnordered(request.getBytes());
            YCSBConfidentialMessage replyMsg = YCSBConfidentialMessage.getObject(reply.getPainData());
            return replyMsg.getResult();
        } catch (SecretSharingException e) {
            e.printStackTrace();
        }
        return -1;
    }

    @Override
    public int scan(String arg0, String arg1, int arg2, Set<String> arg3,
                    Vector<HashMap<String, ByteIterator>> arg4) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int update(String table, String key,
                      HashMap<String, ByteIterator> values) {
        try {
            Iterator<String> valueIt = values.keySet().iterator();

            String[] keys = new String[values.size()];
            byte[][] secrets = new byte[values.size()][];
            int i = 0;
            while (valueIt.hasNext()) {
                String field = valueIt.next();
                keys[i] = field;
                secrets[i] = values.get(field).toArray();
                i++;
            }
            YCSBConfidentialMessage msg = YCSBConfidentialMessage.newUpdateRequest(table, key, keys);
            Response reply = proxy.invokeOrdered(msg.getBytes(), secrets);
            YCSBConfidentialMessage replyMsg = YCSBConfidentialMessage.getObject(reply.getPainData());
            return replyMsg.getResult();
        } catch (SecretSharingException e) {
            e.printStackTrace();
        }
        return -1;
    }

}
