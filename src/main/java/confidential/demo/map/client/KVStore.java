package confidential.demo.map.client;

import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.facade.SecretSharingException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.LinkedList;
import java.util.List;

public class KVStore {
	private Logger logger = LoggerFactory.getLogger("demo");
	private ConfidentialServiceProxy service;
	
	public KVStore(int clientId) throws SecretSharingException {
		this.service = new ConfidentialServiceProxy(clientId);
	}
	
	public void close() {
		service.close();
	}
	
	public String put(String key, String value) {
		try {
			Response response = service.invokeOrdered(serialize(Operation.PUT, key), value.getBytes());
			return response.getConfidentialData() != null && response.getConfidentialData().length > 0
					? new String(response.getConfidentialData()[0]) : null;
		} catch (SecretSharingException e) {
			logger.error("Put failed", e);
		}
		return null;
	}
	
	public String get(String key) {
		try {
			Response response = service.invokeOrdered(serialize(Operation.GET, key));
			return response.getConfidentialData() != null && response.getConfidentialData().length > 0
					? new String(response.getConfidentialData()[0]) : null;
		} catch (SecretSharingException e) {
			logger.error("Get failed", e);
		}
		return null;
	}
	
	public String remove(String key) {
		try {
			Response response = service.invokeOrdered(serialize(Operation.REMOVE, key));
			return response.getConfidentialData() != null && response.getConfidentialData().length > 0
					? new String(response.getConfidentialData()[0]) : null;
		} catch (SecretSharingException e) {
			logger.error("Remove failed", e);
		}
		return null;
	}
	
	public List<String> getAll() {
		List<String> result = new LinkedList<>();
		try {
			Response response = service.invokeOrdered(serialize(Operation.GET_ALL, null));
			if (response.getConfidentialData() == null)
				return result;
			for (byte[] secret : response.getConfidentialData())
				result.add(new String(secret));
		} catch (SecretSharingException e) {
			logger.error("Remove failed", e);
		}

		return result;
	}
	
	private byte[] serialize(Operation op, String str) {
		try(ByteArrayOutputStream bos = new ByteArrayOutputStream();
				ObjectOutput out = new ObjectOutputStream(bos)) {
			out.write((byte)op.ordinal());
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
}
