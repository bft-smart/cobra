package confidential.benchmark;

import confidential.client.Response;
import confidential.demo.map.client.Operation;
import confidential.encrypted.EncryptedPublishedShares;
import vss.facade.SecretSharingException;

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
        if (args.length != 7) {
            System.out.println("USAGE: ... PreComputedKVStoreClient <initial client id> " +
                    "<num clients> <number of ops> <request size> <write?> <precomputed?> <measurement leader?>");
            System.exit(-1);
        }

        initialId = Integer.parseInt(args[0]);
        int numClients = Integer.parseInt(args[1]);
        int numOperations = Integer.parseInt(args[2]);
        int requestSize = Integer.parseInt(args[3]);
        boolean write = Boolean.parseBoolean(args[4]);
        boolean precomputed = Boolean.parseBoolean(args[5]);
        boolean measurementLeader = Boolean.parseBoolean(args[6]);

        Random random = new Random(1L);
        byte[] data = new byte[requestSize];
        random.nextBytes(data);
        String key = "key";
        byte[] plainWriteData = serialize(Operation.PUT, key);
        byte[] plainReadData = serialize(Operation.GET, key);

        Client[] clients = new Client[numClients];
        if (precomputed) {
            PreComputedProxy generatorProxy = new PreComputedProxy(initialId - 1);
            EncryptedPublishedShares[] shares = generatorProxy.sharePrivateData(data);
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

            byte[] unorderedCommonData = generatorProxy.serializeCommonData(plainReadData, null);

            for (int i = 0; i < numClients; i++) {
                int sleepTime = random.nextInt(50);
                Thread.sleep(sleepTime);
                PreComputedProxy proxy = new PreComputedProxy(initialId + i);
                proxy.setPreComputedValues(data, plainWriteData, plainReadData, shares, orderedCommonData, privateData, unorderedCommonData);
                clients[i] = new Client(initialId + i, proxy, true, numOperations, plainWriteData,
                        plainReadData, data, write, measurementLeader);
            }
            generatorProxy.close();
        } else {
            for (int i = 0; i < numClients; i++) {
                int sleepTime = random.nextInt(50);
                Thread.sleep(sleepTime);
                PreComputedProxy proxy = new PreComputedProxy(initialId + i);
                clients[i] = new Client(initialId + i, proxy, true, numOperations, plainWriteData,
                        plainReadData, data, write, measurementLeader);
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
        System.out.println("Experiment ended");
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
        private final boolean measurementLeader;
        private final boolean preComputed;
        private int rampup = 1000;

        Client(int id, PreComputedProxy proxy, boolean precomputed, int numOperations,
               byte[] plainWriteData, byte[] plainReadData, byte[] data, boolean write,
               boolean measurementLeader) {
            super("Client " + id);
            this.id = id;
            this.numOperations = numOperations;
            this.plainWriteData = plainWriteData;
            this.plainReadData = plainReadData;
            this.data = data;
            this.write = write;
            this.preComputed = precomputed;
            this.proxy = proxy;
            this.measurementLeader = measurementLeader;
        }

        @Override
        public void run() {
            try {
                if (id == initialId) {
                    if (measurementLeader)
                        System.out.println("I'm measurement leader");
                    System.out.println("Sending test data...");
                }
                proxy.invokeOrdered(plainWriteData, data);
                Response response = proxy.invokeUnordered(plainReadData);
                if (!preComputed && !Arrays.equals(response.getConfidentialData()[0], data))
                    throw new RuntimeException("Wrong response");

                if (id == initialId) {
                    System.out.println("Executing experiment for " + numOperations + " ops");
                }
                for (int i = 0; i < numOperations - 1; i++) {
                    long t2;
                    long t1 = System.nanoTime();
                    if (write) {
                        proxy.invokeOrdered(plainWriteData, data);
                    } else {
                        proxy.invokeUnordered(plainReadData);
                    }
                    t2 = System.nanoTime();
                    long latency = t2 - t1;

                    if (id == initialId && measurementLeader)
                        System.out.println("M: " + latency);

                    try {
                        if (rampup > 0) {
                            Thread.sleep(rampup);
                            rampup -= 100;
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
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
