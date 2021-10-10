package confidential.demo.statechecker;

import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import vss.facade.SecretSharingException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;

public class Reader {
    private final ConfidentialServiceProxy service;

    public Reader(int clientId) throws SecretSharingException {
        service = new ConfidentialServiceProxy(clientId);
    }

    public String read(String key) throws SecretSharingException {
        Response response = service.invokeOrdered(serialize(key));
        return response.getConfidentialData() != null && response.getConfidentialData().length > 0
                ? new String(response.getConfidentialData()[0]) : null;
    }

    private byte[] serialize(String str) {
        try(ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutput out = new ObjectOutputStream(bos)) {
            out.write((byte) Operation.GET.ordinal());
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
