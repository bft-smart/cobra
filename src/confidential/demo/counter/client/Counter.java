package confidential.demo.counter.client;

import confidential.client.ConfidentialServiceProxy;
import vss.facade.SecretSharingException;

public class Counter {
    private ConfidentialServiceProxy service;

    public Counter(int clientId) throws SecretSharingException {
        this.service = new ConfidentialServiceProxy(clientId);
    }

    public void close() {
        service.close();
    }

    public String incrementOrdered() throws SecretSharingException {
        return new String(service.invokeOrdered(new byte[0]).getPainData());
    }

    public String incrementUnordered() throws SecretSharingException {
        return new String(service.invokeUnordered(new byte[0]).getPainData());
    }
}
