package confidential.demo.statechecker;

import confidential.client.ConfidentialServiceProxy;
import vss.facade.SecretSharingException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;

public class Writer {
    private final ConfidentialServiceProxy service;

    public Writer(int clientId) throws SecretSharingException {
        service = new ConfidentialServiceProxy(clientId);
    }

    public void write(String key, String value) throws SecretSharingException {
        service.invokeOrdered(serialize(key), value.getBytes());
    }

    private byte[] serialize(String str) {
        try(ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutput out = new ObjectOutputStream(bos)) {
            out.write((byte) Operation.PUT.ordinal());
            if(str != null)
                out.writeUTF(str);
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void close() {
        service.close();
    }
}
