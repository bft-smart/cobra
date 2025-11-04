package confidential.benchmark;

import confidential.client.ConfidentialServiceProxy;
import confidential.encrypted.EncryptedPublishedShares;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import vss.facade.SecretSharingException;

import java.util.*;
import java.util.concurrent.*;

/**
 * @author Robin
 */
public class PreComputedKVStoreClient {
	private final static Logger logger = LoggerFactory.getLogger("benchmarking");
	private static int initialId;

	public static void main(String[] args) throws SecretSharingException, InterruptedException {
		if (args.length != 11) {
			System.out.println("USAGE: ... PreComputedKVStoreClient <initial client id> " +
					"<num clients> <number of ops> <request plain data size> <request private data size> " +
					"<response plain data size> <response plain data size> <sendOrderedRequest?> " +
					"<use hashed response> <precomputed?> <measurement leader?>");
			System.exit(-1);
		}

		initialId = Integer.parseInt(args[0]);
		int numClients = Integer.parseInt(args[1]);
		int numOperations = Integer.parseInt(args[2]);
		int requestPlainDataSize = Integer.parseInt(args[3]);
		int requestPrivateDataSize = Integer.parseInt(args[4]);
		int responsePlainDataSize = Integer.parseInt(args[5]);
		int responsePrivateDataSize = Integer.parseInt(args[6]);
		boolean sendOrderedRequest = Boolean.parseBoolean(args[7]);
		boolean useHashedResponse = Boolean.parseBoolean(args[8]);
		boolean precomputed = Boolean.parseBoolean(args[9]);
		boolean measurementLeader = Boolean.parseBoolean(args[10]);

		if (responsePlainDataSize > 0 || responsePrivateDataSize > 0) {
			byte[] responsePlainData = new byte[responsePlainDataSize + 1];
			responsePlainData[0] = 1;
			for (int i = 1; i <= responsePlainDataSize; i++) {
				responsePlainData[i] = (byte) i;
			}
			byte[] responsePrivateData = new byte[responsePrivateDataSize];
			for (int i = 0; i < responsePrivateDataSize; i++) {
				responsePrivateData[i] = (byte) i;
			}
			ConfidentialServiceProxy proxy = new ConfidentialServiceProxy(initialId);
			if (responsePrivateDataSize == 0)
				proxy.invokeOrderedHashed(responsePlainData);
			else
				proxy.invokeOrderedHashed(responsePlainData, responsePrivateData);
			proxy.close();
		}

		Random random = new Random(1L);
		byte[] plainData = new byte[requestPlainDataSize];
		for (int i = 0; i < requestPlainDataSize; i++) {
			plainData[i] = (byte) i;
		}
		byte[] privateData = new byte[requestPrivateDataSize];
		for (int i = 0; i < requestPrivateDataSize; i++) {
			privateData[i] = (byte) i;
		}

		Client[] clients = new Client[numClients];
		if (precomputed) {
			PreComputedProxy generatorProxy = new PreComputedProxy(initialId);
			EncryptedPublishedShares[] shares = null;
			if (requestPrivateDataSize > 0) {
				shares = generatorProxy.sharePrivateData(privateData);
			}
			byte[] commonData = generatorProxy.serializeCommonData(plainData, shares);
			if (commonData == null) {
				throw new RuntimeException("Failed to serialize request");
			}

			int[] servers = generatorProxy.service.getViewManager().getCurrentViewProcesses();
			Map<Integer, byte[]> privateDataShares = new HashMap<>(servers.length);
			if (shares != null) {
				for (int server : servers) {
					byte[] b = generatorProxy.serializePrivateDataFor(server, shares);
					privateDataShares.put(server, b);
				}
			}
			generatorProxy.close();

			for (int i = 0; i < numClients; i++) {
				int sleepTime = random.nextInt(1000);
				Thread.sleep(sleepTime);
				PreComputedProxy proxy = new PreComputedProxy(initialId + i);
				proxy.setPreComputedValues(plainData, privateData, shares, commonData, privateDataShares);
				clients[i] = new Client(initialId + i, proxy, numOperations, sendOrderedRequest, useHashedResponse,
						plainData, privateData,measurementLeader);
			}
		} else {
			for (int i = 0; i < numClients; i++) {
				int sleepTime = random.nextInt(1000);
				Thread.sleep(sleepTime);
				PreComputedProxy proxy = new PreComputedProxy(initialId + i);
				clients[i] = new Client(initialId + i, proxy, numOperations, sendOrderedRequest, useHashedResponse,
						plainData, privateData, measurementLeader);
			}
		}

		ExecutorService executorService = Executors.newFixedThreadPool(numClients);
		Collection<Future<?>> tasks = new LinkedList<>();
		Random rndGenerator = new Random();
		for (Client client : clients) {
			try {
				Thread.sleep(rndGenerator.nextInt(50));
			} catch (InterruptedException e) {
				logger.error("Interrupted while starting clients", e);
			}
			tasks.add(executorService.submit(client));
		}
		logger.info("Executing experiment");
		Runtime.getRuntime().addShutdownHook(new Thread(executorService::shutdownNow));

		for (Future<?> task : tasks) {
			try {
				task.get();
			} catch (InterruptedException | ExecutionException e) {
				logger.error("Error while executing client", e);
				executorService.shutdownNow();
				System.exit(-1);
			}
		}
		executorService.shutdown();
		System.out.println("Experiment ended");
	}

	private static class Client extends Thread {
		private final Logger measurementLogger = LoggerFactory.getLogger("measurement");
		private final int id;
		private final int numOperations;
		private final boolean sendOrderedRequest;
		private final boolean useHashedResponse;
		private final byte[] plainData;
		private final byte[] privateData;
		private final PreComputedProxy proxy;
		private final boolean measurementLeader;
		private int rampUp = 1000;

		Client(int id, PreComputedProxy proxy, int numOperations,
			   boolean sendOrderedRequest, boolean useHashedResponse, byte[] plainData,
			   byte[] privateData, boolean measurementLeader) {
			super("Client " + id);
			this.id = id;
			this.numOperations = numOperations;
			this.sendOrderedRequest = sendOrderedRequest;
			this.plainData = plainData;
			this.privateData = privateData;
			this.proxy = proxy;
			this.measurementLeader = measurementLeader;
			this.useHashedResponse = useHashedResponse;
		}

		@Override
		public void run() {
			try {
				for (int i = 0; i < numOperations; i++) {
					long t1, t2, latency;
					t1 = System.nanoTime();
					if (sendOrderedRequest) {
						if (useHashedResponse) {
							if (privateData.length == 0)
								proxy.invokeOrderedHashed(plainData);
							else
								proxy.invokeOrderedHashed(plainData, privateData);
						} else {
							if (privateData.length == 0)
								proxy.invokeOrdered(plainData);
							else
								proxy.invokeOrdered(plainData, privateData);
						}
					} else {
						if (useHashedResponse) {
							if (privateData.length == 0)
								proxy.invokeUnorderedHashed(plainData);
							else
								proxy.invokeUnorderedHashed(plainData, privateData);
						} else {
							if (privateData.length == 0)
								proxy.invokeUnordered(plainData);
							else
								proxy.invokeUnordered(plainData, privateData);
						}
					}
					t2 = System.nanoTime();
					latency = t2 - t1;

					if (id == initialId && measurementLeader) {
						measurementLogger.info("M-global: {}", latency);
					}

					if (rampUp > 0) {
						Thread.sleep(rampUp);
						rampUp -= 100;
					}
				}

			} catch (SecretSharingException | InterruptedException e) {
				logger.error("Client {} interrupted with exception", id, e);
			} finally {
				proxy.close();
			}
		}

		@Override
		public void interrupt() {
			proxy.close();
			super.interrupt();
		}
	}
}
