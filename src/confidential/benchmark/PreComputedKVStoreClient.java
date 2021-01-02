package confidential.benchmark;

import confidential.client.Response;
import confidential.demo.map.client.Operation;
import vss.facade.SecretSharingException;
import vss.secretsharing.PrivatePublishedShares;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * @author Robin
 */
public class PreComputedKVStoreClient {
    private static int initialId;

    public static void main(String[] args) throws SecretSharingException, InterruptedException {
        if (args.length != 6) {
            System.out.println("USAGE: ... PreComputedKVStoreClient <initial client id> " +
                    "<num clients> <number of ops> <request size> <write?> <precomputed?>");
            System.exit(-1);
        }

        initialId = Integer.parseInt(args[0]);
        int numClients = Integer.parseInt(args[1]);
        int numOperations = Integer.parseInt(args[2]);
        int requestSize = Integer.parseInt(args[3]);
        boolean write = Boolean.parseBoolean(args[4]);
        boolean precomputed = Boolean.parseBoolean(args[5]);

        Random random = new Random(1L);
        byte[] data = new byte[requestSize];
        random.nextBytes(data);
        String key = "key";
        byte[] plainWriteData = serialize(Operation.PUT, key);
        byte[] plainReadData = serialize(Operation.GET, key);

        Client[] clients = new Client[numClients];
        if (precomputed) {
            PreComputedProxy generatorProxy = new PreComputedProxy(initialId - 1);
            PrivatePublishedShares[] shares = generatorProxy.sharePrivateData(data);
            byte[] orderedCommonData = generatorProxy.serializeCommonData(plainWriteData, shares);
            if (orderedCommonData == null) {
                throw new RuntimeException("Failed to serialize common data");
            }

            int[] servers = generatorProxy.service.getViewManager().getCurrentViewProcesses();
            Map<Integer, byte[]> privateData = new HashMap<>(servers.length);
            for (int server : servers) {
                byte[] b = generatorProxy.serializePrivateDataFor(server, shares);
                privateData.put(server, b);
            }

            byte[] unorderedCommonData = generatorProxy.serializeCommonData(plainReadData, shares);

            for (int i = 0; i < numClients; i++) {
                int sleepTime = random.nextInt(50);
                Thread.sleep(sleepTime);
                PreComputedProxy proxy = new PreComputedProxy(initialId + i, unorderedCommonData,
                        orderedCommonData, privateData);
                clients[i] = new Client(initialId + i, proxy, true, numOperations, plainWriteData,
                        plainReadData, data, write);
            }
            generatorProxy.close();
        } else {
            for (int i = 0; i < numClients; i++) {
                int sleepTime = random.nextInt(50);
                Thread.sleep(sleepTime);
                PreComputedProxy proxy = new PreComputedProxy(initialId + i);
                clients[i] = new Client(initialId + i, proxy, true, numOperations, plainWriteData,
                        plainReadData, data, write);
            }
        }

        ExecutorService executorService = Executors.newFixedThreadPool(numClients);
        Collection<Future<?>> tasks = new LinkedList<>();
        Random rndGenerator = new Random();
        for (Client client : clients) {
            try {
                Thread.sleep(rndGenerator.nextInt(50));
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            tasks.add(executorService.submit(client));
        }
        Runtime.getRuntime().addShutdownHook(new Thread(executorService::shutdownNow));

        for (Future<?> task : tasks) {
            try {
                task.get();
            } catch (InterruptedException | ExecutionException e) {
                e.printStackTrace();
                executorService.shutdownNow();
                System.exit(-1);
            }
        }

        executorService.shutdown();
    }

    private static byte[] serialize(Operation op, String str) {
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

    private static class Client extends Thread {
        private final int id;
        private final int numOperations;
        private final byte[] plainWriteData;
        private final byte[] plainReadData;
        private final byte[] data;
        private final boolean write;
        private final PreComputedProxy proxy;
        private final boolean preComputed;
        private int rampup = 1000;

        Client(int id, PreComputedProxy proxy, boolean precomputed, int numOperations,
               byte[] plainWriteData, byte[] plainReadData, byte[] data, boolean write) {
            super("Client " + id);
            this.id = id;
            this.numOperations = numOperations;
            this.plainWriteData = plainWriteData;
            this.plainReadData = plainReadData;
            this.data = data;
            this.write = write;
            this.preComputed = precomputed;
            this.proxy = proxy;
        }

        @Override
        public void run() {
            if (id == initialId)
                System.out.println("Warming up...");
            try {
                proxy.invokeOrdered(plainWriteData, data);
                Response response;
                for (int i = 0; i < 50; i++) {
                    if (write)
                        proxy.invokeOrdered(plainWriteData, data);
                    else {
                        response = proxy.invokeUnordered(plainReadData);
                        if (!preComputed && !Arrays.equals(response.getConfidentialData()[0], data))
                            throw new RuntimeException("Wrong response");
                    }
                }
                //Storage st = new Storage(numOperations);
                long[] latencies = null;
                if (id == initialId) {
                    latencies = new long[numOperations];
                    System.out.println("Executing experiment for " + numOperations + " ops");
                }
                for (int i = 0; i < numOperations; i++) {
                    long t2;
                    long t1 = System.nanoTime();
                    if (write) {
                        proxy.invokeOrdered(plainWriteData, data);
                    } else {
                        proxy.invokeUnordered(plainReadData);
                    }
                    t2 = System.nanoTime();
                    long latency = t2 - t1;
                    if (latencies != null) {
                        latencies[i] = latency;
                    }
                    try {
                        if (rampup > 0) {
                            Thread.sleep(rampup);
                            rampup -= 100;
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }

                if (latencies != null) {
                    StringBuilder sb = new StringBuilder();
                    for (long latency : latencies) {
                        sb.append(latency);
                        sb.append(" ");
                    }
                    System.out.println("M: " + sb.toString().trim());
                    //System.out.println("Average time for " + numOperations + " executions (-10%) = " + st.getAverage(true) / 1000 + " us ");
                    //System.out.println("Standard deviation for " + numOperations + " executions (-10%) = " + st.getDP(true) / 1000 + " us ");
                    //System.out.println("Average time for " + numOperations + " executions (all samples) = " + st.getAverage(false) / 1000 + " us ");
                    //System.out.println("Standard deviation for " + numOperations + " executions (all samples) = " + st.getDP(false) / 1000 + " us ");
                    //System.out.println("Maximum time for " + numOperations + " executions (all samples) = " + st.getMax(false) / 1000 + " us ");
                }

            } catch (SecretSharingException e) {
                e.printStackTrace();
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
