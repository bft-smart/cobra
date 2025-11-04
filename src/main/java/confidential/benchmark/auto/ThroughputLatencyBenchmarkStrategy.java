package confidential.benchmark.auto;

import controller.IBenchmarkStrategy;
import controller.IWorkerStatusListener;
import controller.WorkerHandler;
import generic.DefaultMeasurements;
import generic.ResourcesMeasurements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import util.Storage;
import worker.IProcessingResult;
import worker.ProcessInformation;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * @author robin
 */
public class ThroughputLatencyBenchmarkStrategy implements IBenchmarkStrategy, IWorkerStatusListener {
	private final Logger logger = LoggerFactory.getLogger("benchmarking");
	private final Lock lock;
	private final Condition sleepCondition;
	private final String serverCommand;
	private final String clientCommand;
	private final String sarCommand;
	private final Set<Integer> serverWorkersIds;
	private final Set<Integer> clientWorkersIds;
	private WorkerHandler[] clientWorkers;
	private WorkerHandler[] serverWorkers;
	private final Map<Integer, WorkerHandler> measurementWorkers;
	private CountDownLatch workersReadyCounter;
	private CountDownLatch measurementDeliveredCounter;
	private String storageFileNamePrefix;
	private String performanceFileNamePrefix;
	private int round;

	//Storing data for plotting
	private double[] latencyValues;
	private double[] latencyStdValues;
	private double[] throughputValues;
	private double[] throughputStdValues;

	public ThroughputLatencyBenchmarkStrategy() {
		this.lock = new ReentrantLock(true);
		this.sleepCondition = lock.newCondition();
		String initialCommand = "java -Xmx28g -Djava.security.properties=./config/java" +
				".security -Dlogback.configurationFile=./config/logback.xml -cp lib/* ";
		this.serverCommand = initialCommand + "confidential.benchmark.ThroughputLatencyKVStoreServer ";
		this.clientCommand = initialCommand + "confidential.benchmark.PreComputedKVStoreClient ";
		this.sarCommand = "sar -u -r -n DEV 1";
		this.serverWorkersIds = new HashSet<>();
		this.clientWorkersIds = new HashSet<>();
		this.measurementWorkers = new HashMap<>();
	}

	@Override
	public void executeBenchmark(WorkerHandler[] workers, Properties benchmarkParameters) {
		long startTime = System.currentTimeMillis();
		int f = Integer.parseInt(benchmarkParameters.getProperty("experiment.f"));
		String[] tokens = benchmarkParameters.getProperty("experiment.clients_per_round").split(" ");
		int requestPlainDataSize = Integer.parseInt(benchmarkParameters.getProperty("experiment.request.plain_data_size"));
		int requestPrivateDataSize = Integer.parseInt(benchmarkParameters.getProperty("experiment.request.private_data_size"));
		int responsePlainDataSize = Integer.parseInt(benchmarkParameters.getProperty("experiment.response.plain_data_size"));
		int responsePrivateDataSize = Integer.parseInt(benchmarkParameters.getProperty("experiment.response.private_data_size"));
		boolean sendOrderedRequest = Boolean.parseBoolean(benchmarkParameters.getProperty("experiment.send_ordered_request"));
		boolean useHashedResponse = Boolean.parseBoolean(benchmarkParameters.getProperty("experiment.use_hashed_response"));
		String hostFile = benchmarkParameters.getProperty("experiment.hosts.file");
		boolean measureResources = Boolean.parseBoolean(benchmarkParameters.getProperty("experiment.measure_resources"));
		int measurementDuration = Integer.parseInt(benchmarkParameters.getProperty("experiment.measurement_duration"));


		int nServerWorkers = 3 * f + 1;
		int nClientWorkers = workers.length - nServerWorkers;
		int maxClientsPerProcess = 30;
		int nRequests = 10_000_000;
		int sleepBetweenRounds = 10;
		int[] clientsPerRound = new int[tokens.length];
		for (int i = 0; i < tokens.length; i++) {
			clientsPerRound[i] = Integer.parseInt(tokens[i]);
		}
		int nRounds = clientsPerRound.length;
		latencyValues = new double[nRounds];
		latencyStdValues = new double[nRounds];
		throughputValues = new double[nRounds];
		throughputStdValues = new double[nRounds];

		//Separate workers
		serverWorkers = new WorkerHandler[nServerWorkers];
		clientWorkers = new WorkerHandler[nClientWorkers];
		System.arraycopy(workers, 0, serverWorkers, 0, nServerWorkers);
		System.arraycopy(workers, nServerWorkers, clientWorkers, 0, nClientWorkers);
		Arrays.sort(clientWorkers, (o1, o2) -> -Integer.compare(o1.getWorkerId(), o2.getWorkerId()));
		Arrays.stream(serverWorkers).forEach(w -> serverWorkersIds.add(w.getWorkerId()));
		Arrays.stream(clientWorkers).forEach(w -> clientWorkersIds.add(w.getWorkerId()));

		printWorkersInfo();

		//Setup workers
		if (hostFile != null) {
			logger.info("Setting up workers...");
			String hosts = loadHosts(hostFile);
			if (hosts == null)
				return;
			String setupInformation = String.format("%b\t%d\t%s", true, f, hosts);
			Arrays.stream(workers).forEach(w -> w.setupWorker(setupInformation));
		}

		performanceFileNamePrefix = String.format("f_%d_%d_%d_%d_%d_bytes_%s_request_%s_response_", f, requestPlainDataSize,
				requestPrivateDataSize, responsePlainDataSize, responsePrivateDataSize,
				sendOrderedRequest ? "ordered" : "unordered", useHashedResponse ? "hashed" : "full");

		System.out.println("f: " + f);
		System.out.println("Request plain data size: " + requestPlainDataSize + " bytes");
		System.out.println("Request private data size: " + requestPrivateDataSize + " bytes");
		System.out.println("Response plain data size: " + responsePlainDataSize + " bytes");
		System.out.println("Response private data size: " + responsePrivateDataSize + " bytes");
		System.out.println("Send ordered request: " + sendOrderedRequest);
		System.out.println("Use hashed response: " + useHashedResponse);
		System.out.println("Measure resources: " + measureResources);

		round = 1;
		while (true) {
			try {
				lock.lock();
				logger.info("============ Round {} out of {} ============", round, nRounds);
				measurementWorkers.clear();
				int nClients = clientsPerRound[round - 1];
				storageFileNamePrefix = String.format("f_%d_%d_%d_%d_%d_bytes_%s_request_%s_response_clients_%d_", f, requestPlainDataSize,
						requestPrivateDataSize, responsePlainDataSize, responsePrivateDataSize,
						sendOrderedRequest ? "ordered" : "unordered", useHashedResponse ? "hashed" : "full", nClients);

				//Distribute clients per workers
				int[] clientsPerWorker = distributeClientsPerWorkers(nClientWorkers, nClients);
				String vector = Arrays.toString(clientsPerWorker);
				int total = Arrays.stream(clientsPerWorker).sum();
				logger.info("Clients per worker: {} -> Total: {}", vector, total);

				//Start servers
				startServers(serverWorkers);

				//Start clients
				startClients(maxClientsPerProcess, nRequests, requestPlainDataSize, requestPrivateDataSize,
						responsePlainDataSize, responsePrivateDataSize, sendOrderedRequest, useHashedResponse,
						clientWorkers, clientsPerWorker);

				//Start resource measurement
				if (measureResources) {
					int nServerResourceMeasurementWorkers = serverWorkers.length > 1 ? 2 : 1;
					int nClientResourceMeasurementWorkers = clientWorkers.length > 1 ? 2 : 1;
					nClientResourceMeasurementWorkers = Math.min(nClientResourceMeasurementWorkers,
							clientsPerWorker.length); // this is to account for 1 client
					startResourceMeasurements(nServerResourceMeasurementWorkers, nClientResourceMeasurementWorkers);
				}

				//Wait for system to stabilize
				logger.info("Waiting 10s...");
				sleepSeconds(10);

				//Get measurements
				getMeasurements(measureResources, measurementDuration);

				//Stop processes
				Arrays.stream(workers).forEach(WorkerHandler::stopWorker);

				if (round == nRounds) {
					break;
				}

				//Wait between round
				logger.info("Waiting {}s before new round", sleepBetweenRounds);
				sleepSeconds(sleepBetweenRounds);
				round++;
			} catch (InterruptedException e) {
				break;
			} finally {
				lock.unlock();
			}
		}

		storeProcessedResults(clientsPerRound);

		long endTime = System.currentTimeMillis();
		logger.info("Strategy execution duration: {}s", (endTime - startTime) / 1000);
	}

	private void storeProcessedResults(int[] clientsPerRound) {
		String fileName = performanceFileNamePrefix + "throughput_latency_results.dat";
		try (BufferedWriter resultFile = new BufferedWriter(new OutputStreamWriter(
				Files.newOutputStream(Paths.get(fileName))))) {
			resultFile.write("#clients throughput[ops/s] throughput_dev[ops/s] latency[ms] latency_dev[ms]\n");
			for (int i = 0; i < clientsPerRound.length; i++) {
				resultFile.write(String.format("%d %.3f %.3f %.3f %.3f\n", clientsPerRound[i],
						throughputValues[i], throughputStdValues[i],
						latencyValues[i], latencyStdValues[i]));
			}
		} catch (IOException e) {
			logger.error("Error while storing processed results", e);
		}
	}

	private void startResourceMeasurements(int nServerResourceMeasurementWorkers,
										   int nClientResourceMeasurementWorkers) throws InterruptedException {
		WorkerHandler[] resourceMeasurementWorkers =
				new WorkerHandler[nServerResourceMeasurementWorkers + nClientResourceMeasurementWorkers];
		System.arraycopy(serverWorkers, 0, resourceMeasurementWorkers, 0, nServerResourceMeasurementWorkers);
		System.arraycopy(clientWorkers, 0, resourceMeasurementWorkers, nServerResourceMeasurementWorkers,
				nClientResourceMeasurementWorkers);

		logger.info("Starting resource measurements...");
		workersReadyCounter = new CountDownLatch(resourceMeasurementWorkers.length);
		for (WorkerHandler worker : resourceMeasurementWorkers) {
			measurementWorkers.put(worker.getWorkerId(), worker);
			ProcessInformation[] commands = {
					new ProcessInformation(sarCommand, ".")
			};
			worker.startWorker(0, commands, this);
		}
		workersReadyCounter.await();
	}

	private void printWorkersInfo() {
		StringBuilder sb = new StringBuilder();
		for (WorkerHandler serverWorker : serverWorkers) {
			sb.append(serverWorker.getWorkerId());
			sb.append(" ");
		}
		logger.info("Server workers: {}", sb);

		sb = new StringBuilder();
		for (WorkerHandler clientWorker : clientWorkers) {
			sb.append(clientWorker.getWorkerId());
			sb.append(" ");
		}
		logger.info("Client workers: {}", sb);
	}

	private String loadHosts(String hostFile) {
		try (BufferedReader in = new BufferedReader(new FileReader(hostFile))) {
			StringBuilder sb = new StringBuilder();
			String line;
			while ((line = in.readLine()) != null) {
				sb.append(line);
				sb.append("\n");
			}
			sb.deleteCharAt(sb.length() - 1);
			return sb.toString();
		} catch (IOException e) {
			logger.error("Failed to load hosts file", e);
			return null;
		}
	}

	private void getMeasurements(boolean measureResources, int measurementDuration) throws InterruptedException {
		//Start measurements
		logger.debug("Starting measurements...");
		measurementWorkers.values().forEach(WorkerHandler::startProcessing);

		//Wait for measurements
		logger.info("Measuring during {}s", measurementDuration);
		sleepSeconds(measurementDuration);

		//Stop measurements
		measurementWorkers.values().forEach(WorkerHandler::stopProcessing);

		//Get measurement results
		int nMeasurements;
		if (measureResources) {
			//servers: 2 + 1
			//clients: 2 + 1
			nMeasurements = measurementWorkers.size() + 2;
		} else {
			nMeasurements = 2;
		}
		logger.debug("Getting {} measurements from {} workers...", nMeasurements, measurementWorkers.size());
		measurementDeliveredCounter = new CountDownLatch(nMeasurements);

		measurementWorkers.values().forEach(WorkerHandler::requestProcessingResult);

		measurementDeliveredCounter.await();
	}

	private void startClients(int maxClientsPerProcess, int nRequests, int requestPlainDataSize,
							  int requestPrivateDataSize, int responsePlainDataSize, int responsePrivateDataSize,
							  boolean sendOrderedRequest, boolean useHashedResponse, WorkerHandler[] clientWorkers,
							  int[] clientsPerWorker) throws InterruptedException {
		logger.info("Starting clients...");
		workersReadyCounter = new CountDownLatch(clientsPerWorker.length);
		int clientInitialId = 100000;
		measurementWorkers.put(clientWorkers[0].getWorkerId(), clientWorkers[0]);

		for (int i = 0; i < clientsPerWorker.length && i < clientWorkers.length; i++) {
			WorkerHandler clientWorker = clientWorkers[i];
			int totalClientsPerWorker = clientsPerWorker[i];
			int nProcesses = totalClientsPerWorker / maxClientsPerProcess
					+ (totalClientsPerWorker % maxClientsPerProcess == 0 ? 0 : 1);

			ProcessInformation[] commandInfos = new ProcessInformation[nProcesses];
			boolean isMeasurementWorker = i == 0;// First client is measurement client

			for (int j = 0; j < nProcesses; j++) {
				int clientsPerProcess = Math.min(totalClientsPerWorker, maxClientsPerProcess);
				String command = clientCommand + clientInitialId + " " + clientsPerProcess
						+ " " + nRequests + " " + requestPlainDataSize + " " + requestPrivateDataSize
						+ " " + responsePlainDataSize + " " + responsePrivateDataSize + " " + sendOrderedRequest
						+ " " + useHashedResponse + " " + (!isMeasurementWorker) + " " + isMeasurementWorker;

				commandInfos[j] = new ProcessInformation(command, ".");
				totalClientsPerWorker -= clientsPerProcess;
				clientInitialId += clientsPerProcess;
			}

			clientWorker.startWorker(50, commandInfos, this);
		}
		workersReadyCounter.await();
	}

	private void startServers(WorkerHandler[] serverWorkers) throws InterruptedException {
		logger.info("Starting servers...");
		workersReadyCounter = new CountDownLatch(serverWorkers.length);
		measurementWorkers.put(serverWorkers[0].getWorkerId(), serverWorkers[0]);

		for (int i = 0; i < serverWorkers.length; i++) {
			WorkerHandler serverWorker = serverWorkers[i];
			logger.debug("Using server worker {}", serverWorker.getWorkerId());

			String command = serverCommand + i;

			ProcessInformation[] commandInfo = {
					new ProcessInformation(command, ".")
			};
			serverWorker.startWorker(0, commandInfo, this);
			sleepSeconds(2);
		}

		workersReadyCounter.await();
	}

	private int[] distributeClientsPerWorkers(int nWorkers, int nClients) {
		if (nClients == 1 || nWorkers == 1) {
			return new int[]{nClients};
		}

		nClients--;//remove measurement client
		nWorkers--; //Subtract the measurement client

		if (nClients <= nWorkers) {
			int[] distribution = new int[1 + nClients];
			Arrays.fill(distribution, 1);
			return distribution;
		}

		int[] distribution = new int[1 + nWorkers];
		int nClientsPerWorker = nClients / nWorkers;

		Arrays.fill(distribution, nClientsPerWorker);
		distribution[0] = 1;//Measurement client

		int remainingClients = nClients % nWorkers;
		for (int i = 1; i <= remainingClients; i++) {
			distribution[i]++;
		}
		return distribution;
	}

	private void processResourcesMeasurements(ResourcesMeasurements resourcesMeasurements, String tag) {
		long[] cpu = resourcesMeasurements.getCpu();
		long[] mem = resourcesMeasurements.getMemory();
		long[][] netReceived = resourcesMeasurements.getNetReceived();
		long[][] netTransmitted = resourcesMeasurements.getNetTransmitted();

		String fileName = storageFileNamePrefix + "cpu_" + tag + ".csv";
		saveResourcesMeasurements(fileName, cpu);

		fileName = storageFileNamePrefix + "mem_" + tag + ".csv";
		saveResourcesMeasurements(fileName, mem);

		fileName = storageFileNamePrefix + "net_received_" + tag + ".csv";
		saveResourcesMeasurements(fileName, netReceived);

		fileName = storageFileNamePrefix + "net_transmitted_" + tag + ".csv";
		saveResourcesMeasurements(fileName, netTransmitted);
	}

	private void saveResourcesMeasurements(String fileName, long[]... data) {
		try (BufferedWriter resultFile = new BufferedWriter(new OutputStreamWriter(
				Files.newOutputStream(Paths.get(fileName))))) {
			int size = data[0].length;
			int i = 0;
			while (i < size) {
				StringBuilder sb = new StringBuilder();
				for (long[] datum : data) {
					sb.append(String.format("%.2f", datum[i] / 100.0));
					sb.append(",");
				}
				sb.deleteCharAt(sb.length() - 1);
				resultFile.write(sb + "\n");
				i++;
			}
			resultFile.flush();
		} catch (IOException e) {
			logger.error("Error while storing resources measurements results", e);
		}
	}

	private void processClientMeasurement(DefaultMeasurements clientMeasurements) {
		saveClientMeasurements(clientMeasurements.getMeasurements());

		long[] globalLatencies = clientMeasurements.getMeasurements("global");
		Storage st = new Storage(globalLatencies);

		latencyValues[round - 1] = st.getAverage(true) / 1_000_000.0;
		latencyStdValues[round - 1] = st.getDP(true) / 1_000_000.0;

		String sb = String.format("Client-side measurements [%d samples]:\n", globalLatencies.length) +
				String.format("\tLatency[ms]: avg:%.3f dev:%.3f max: %d",
						st.getAverage(true) / 1_000_000.0, st.getDP(true) / 1_000_000.0,
						st.getMax(true) / 1_000_000);
		logger.info(sb);
	}

	private void processServerMeasurement(DefaultMeasurements serverMeasurements) {
		saveServerMeasurements(serverMeasurements.getMeasurements());

		long[] clients = serverMeasurements.getMeasurements("clients");
		long[] delta = serverMeasurements.getMeasurements("delta");
		long[] nRequests = serverMeasurements.getMeasurements("requests");

		int size = Math.min(clients.length, Math.min(delta.length, nRequests.length));
		long[] throughput = new long[size];
		long minClients = Long.MAX_VALUE;
		long maxClients = Long.MIN_VALUE;

		for (int i = 0; i < size; i++) {
			minClients = Long.min(minClients, clients[i]);
			maxClients = Long.max(maxClients, clients[i]);
			throughput[i] = (long) (nRequests[i] / (delta[i] / 1_000_000_000.0));
		}
		Storage st = new Storage(throughput);

		throughputValues[round - 1] = st.getAverage(true);
		throughputStdValues[round - 1] = st.getDP(true);

		String sb = String.format("Server-side measurements [%d samples]:\n", throughput.length) +
				String.format("\tClients[#]: min:%d max:%d\n", minClients, maxClients) +
				String.format("\tThroughput[ops/s]: avg:%.3f dev:%.3f max: %d",
						st.getAverage(true), st.getDP(true),
						st.getMax(true));
		logger.info(sb);
	}

	public void saveServerMeasurements(Map<String, long[]> measurements) {
		String fileName = storageFileNamePrefix + "server_global.csv";
		String header = "";
		PrimitiveIterator.OfLong[] iterators = new PrimitiveIterator.OfLong[measurements.size()];

		header += "clients[#]";
		iterators[0] = Arrays.stream(measurements.get("clients")).iterator();

		header += ",delta[ns]";
		iterators[1] = Arrays.stream(measurements.get("delta")).iterator();

		header += ",requests[#]";
		iterators[2] = Arrays.stream(measurements.get("requests")).iterator();

		saveGlobalMeasurements(fileName, header, iterators);
	}

	public void saveClientMeasurements(Map<String, long[]> measurements) {
		String fileName = storageFileNamePrefix + "client_global.csv";
		String header = "";
		PrimitiveIterator.OfLong[] iterators = new PrimitiveIterator.OfLong[measurements.size()];

		header += "global[ns]";
		iterators[0] = Arrays.stream(measurements.get("global")).iterator();

		saveGlobalMeasurements(fileName, header, iterators);
	}

	private void saveGlobalMeasurements(String fileName, String header, PrimitiveIterator.OfLong[] dataIterators) {
		try (BufferedWriter resultFile = new BufferedWriter(new OutputStreamWriter(
				Files.newOutputStream(Paths.get(fileName))))) {
			resultFile.write(header + "\n");
			boolean hasData = true;
			while(true) {
				StringBuilder sb = new StringBuilder();
				for (PrimitiveIterator.OfLong iterator : dataIterators) {
					if (iterator.hasNext()) {
						sb.append(iterator.next());
						sb.append(",");
					} else {
						hasData = false;
						break;
					}
				}
				if (!hasData) {
					break;
				}
				sb.deleteCharAt(sb.length() - 1);
				resultFile.write(sb + "\n");
			}

			resultFile.flush();
		} catch (IOException e) {
			logger.error("Failed to save client measurements", e);
		}
	}

	private void sleepSeconds(long duration) throws InterruptedException {
		lock.lock();
		ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
		scheduledExecutorService.schedule(() -> {
			lock.lock();
			sleepCondition.signal();
			lock.unlock();
		}, duration, TimeUnit.SECONDS);
		sleepCondition.await();
		scheduledExecutorService.shutdown();
		lock.unlock();
	}

	@Override
	public void onReady(int workerId) {
		logger.debug("Worker {} is ready", workerId);
		workersReadyCounter.countDown();
	}

	@Override
	public void onEnded(int i) {

	}

	@Override
	public void onError(int workerId, String errorMessage) {
		if (serverWorkersIds.contains(workerId)) {
			if (!errorMessage.contains("Impossible to connect to client")) {
				logger.error("Error in server worker {}: {}", workerId, errorMessage);
			}
		} else if (clientWorkersIds.contains(workerId)) {
			if (!errorMessage.contains("Replica disconnected. Connection reset by peer.")) {
				logger.error("Error in client worker {}: {}", workerId, errorMessage);
			}
		} else {
			logger.error("Error in unused worker {}: {}", workerId, errorMessage);
		}
	}

	@Override
	public synchronized void onResult(int workerId, IProcessingResult processingResult) {
		if (!measurementWorkers.containsKey(workerId)) {
			logger.warn("Received measurements results from unused worker {}", workerId);
			return;
		}

		if (processingResult instanceof DefaultMeasurements && workerId == serverWorkers[0].getWorkerId()) {
			logger.debug("Received leader server performance results from worker {}", workerId);
			DefaultMeasurements serverMeasurements = (DefaultMeasurements) processingResult;
			processServerMeasurement(serverMeasurements);
			measurementDeliveredCounter.countDown();
		} else if (processingResult instanceof DefaultMeasurements && workerId == clientWorkers[0].getWorkerId()) {
			logger.debug("Received measurement client performance results from worker {}", workerId);
			DefaultMeasurements clientMeasurements = (DefaultMeasurements) processingResult;
			processClientMeasurement(clientMeasurements);
			measurementDeliveredCounter.countDown();
		} else if (processingResult instanceof ResourcesMeasurements) {
			String tag = null;
			if (workerId == serverWorkers[0].getWorkerId()) {
				logger.debug("Received leader server resources usage results from worker {}", workerId);
				tag = "leader_server";
			} else if (serverWorkers.length > 1 && workerId == serverWorkers[1].getWorkerId()) {
				logger.debug("Received follower server resources usage results from worker {}", workerId);
				tag = "follower_server";
			} else if (workerId == clientWorkers[0].getWorkerId()) {
				logger.debug("Received measurement client resources usage results from worker {}", workerId);
				tag = "measurement_client";
			} else if (clientWorkers.length > 1 && workerId == clientWorkers[1].getWorkerId()) {
				logger.debug("Received load client resources usage results from worker {}", workerId);
				tag = "load_client";
			}

			if (tag != null) {
				ResourcesMeasurements resourcesMeasurements = (ResourcesMeasurements) processingResult;
				processResourcesMeasurements(resourcesMeasurements, tag);
				measurementDeliveredCounter.countDown();
			} else {
				logger.warn("Received resources usage results from unused worker {}", workerId);
			}
		}
	}
}