package confidential.benchmark;

import bftsmart.tom.ServiceProxy;
import bftsmart.tom.util.Storage;
import confidential.demo.map.client.Operation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * @author Robin
 */
public class SmartKVStoreClient {
    private static int initialId;

    public static void main(String[] args) {
        if (args.length != 6) {
            System.out.println("USAGE: ... SmartKVStoreClient <initial client id> " +
                    "<num clients> <number of ops> <request size> <write?> <precomputed?>");
            System.exit(-1);
        }

        initialId = Integer.parseInt(args[0]);
        int numClients = Integer.parseInt(args[1]);
        int numOperations = Integer.parseInt(args[2]);
        int requestSize = Integer.parseInt(args[3]);
        boolean write = Boolean.parseBoolean(args[4]);
        boolean precomputed = Boolean.parseBoolean(args[5]);


        Client[] clients = new Client[numClients];

        for (int i = 0; i < numClients; i++) {
            clients[i] = new Client(initialId + i, precomputed, numOperations, requestSize, write);
        }

        ExecutorService executorService = Executors.newFixedThreadPool(numClients);
        Collection<Future<?>> tasks = new LinkedList<>();

        for (Client client : clients) {
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

    private static class Client extends Thread {
        private int id;
        private int numOperations;
        private boolean write;
        private ServiceProxy proxy;
        private boolean preComputed;
        private int rampup = 1000;
        private byte[] writeRequest;
        private byte[] readRequest;
        private byte[] data;

        Client(int id, boolean precomputed, int numOperations, int requestSize, boolean write) {
            super("Client " + id);
            this.id = id;
            this.numOperations = numOperations;
            this.write = write;
            this.preComputed = precomputed;

            Random random = new Random(1L);
            String key = "k" + id;
            data = new byte[requestSize];
            random.nextBytes(data);
            writeRequest = serialize(Operation.PUT, key, data);
            readRequest = serialize(Operation.GET, key, null);

            this.proxy = new ServiceProxy(id);
        }

        @Override
        public void run() {
            if (id == initialId)
                System.out.println("Warming up...");
            byte[] response;
            try {
                proxy.invokeOrdered(writeRequest, null);
                for (int i = 0; i < 100; i++) {
                    if (write)
                        proxy.invokeOrdered(writeRequest, null);
                    else {
                        response = proxy.invokeUnordered(readRequest, null);
                        if (!preComputed && !Arrays.equals(response, data))
                            throw new RuntimeException("Wrong response");
                    }
                }
                Storage st = new Storage(numOperations);

                if (id == initialId)
                    System.out.println("Executing experiment for " + numOperations + " ops");
                for (int i = 0; i < numOperations; i++) {
                    long t1 = System.nanoTime();
                    long t2;
                    if (write) {
                        proxy.invokeOrdered(writeRequest, null);
                        t2 = System.nanoTime();
                    } else {
                        response = proxy.invokeUnordered(readRequest, null);
                        t2 = System.nanoTime();
                        if (!preComputed && !Arrays.equals(response, data)) {
                            System.out.println("Checking");
                            throw new RuntimeException("Wrong response");
                        }
                    }
                    long latency = t2 - t1;
                    st.store(latency);
                    try {
                        if (rampup > 0) {
                            Thread.sleep(rampup);
                            rampup -= 100;
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }

                if (id == initialId) {
                    System.out.println("Average time for " + numOperations + " executions (-10%) = " + st.getAverage(true) / 1000 + " us ");
                    System.out.println("Standard deviation for " + numOperations + " executions (-10%) = " + st.getDP(true) / 1000 + " us ");
                    System.out.println("Average time for " + numOperations + " executions (all samples) = " + st.getAverage(false) / 1000 + " us ");
                    System.out.println("Standard deviation for " + numOperations + " executions (all samples) = " + st.getDP(false) / 1000 + " us ");
                    System.out.println("Maximum time for " + numOperations + " executions (all samples) = " + st.getMax(false) / 1000 + " us ");
                }

            } finally {
                proxy.close();
            }
        }

        @Override
        public void interrupt() {
            proxy.close();
            super.interrupt();
        }

        private byte[] serialize(Operation op, String str, byte[] data) {
            try(ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutput out = new ObjectOutputStream(bos)) {
                out.write((byte)op.ordinal());
                if(str != null)
                    out.writeUTF(str);
                if (data != null) {
                    out.writeInt(data.length);
                    out.write(data);
                }
                out.flush();
                bos.flush();
                return bos.toByteArray();
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
        }
    }
}
