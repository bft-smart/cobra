package confidential.demo.counter.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.facade.SecretSharingException;

public class Client {
	private static Logger logger = LoggerFactory.getLogger("demo");
	private static final int DEFAULT_CLIENT_ID = 100;
	private static final int DEFAULT_NUM_REQUESTS = 100;

	public static void main(String[] args) {
		Counter counter = null;

		try {
			logger.info("Staring counter with client id {}", DEFAULT_CLIENT_ID);
			counter = new Counter(DEFAULT_CLIENT_ID);

			int numRequests = args.length == 0 ? DEFAULT_NUM_REQUESTS : Integer.parseInt(args[0]);
			logger.info("Sending {} requests", numRequests);

			for  (int i = 0; i < numRequests; i++) {
				String response = counter.incrementOrdered();
				logger.info("Request: {} Response: {}", i, response);
			}

		} catch (SecretSharingException e) {
			logger.error("Demo failed", e);
		} finally {
			if (counter != null)
				counter.close();
		}
	}
}
