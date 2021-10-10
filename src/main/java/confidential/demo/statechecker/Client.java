package confidential.demo.statechecker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.facade.SecretSharingException;

public class Client {
    private static final Logger logger = LoggerFactory.getLogger("demo");
    private static final int DEFAULT_CLIENT_ID = 100;
    private static final int DEFAULT_NUM_REQUESTS = 1000;

    public static void main(String[] args) {
        Writer writer = null;
        Reader reader = null;

        try {
            logger.info("Staring Write with client id {}", DEFAULT_CLIENT_ID);
            writer = new Writer(DEFAULT_CLIENT_ID);

            int numRequests = args.length == 0 ? DEFAULT_NUM_REQUESTS : Integer.parseInt(args[0]);

            logger.info("Writing {} requests", numRequests);
            String value = "cobra";

            for  (int i = 0; i < numRequests; i++) {
                writer.write(String.valueOf(i), value);
            }

            reader = new Reader(DEFAULT_CLIENT_ID + 1);
            logger.info("Reading {} requests", numRequests);

            for (int i = 0; i < numRequests; i++) {
                String result = reader.read(String.valueOf(i));
                if (!result.equals(value)) {
                    throw new RuntimeException("Received different value!!");
                }
            }

        } catch (SecretSharingException e) {
            logger.error("Demo failed", e);
        } finally {
            if (writer != null)
                writer.close();
            if (reader != null) {
                reader.close();
            }
        }
    }
}
