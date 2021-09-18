package confidential.benchmark;

import bftsmart.tom.ServiceProxy;
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
                    "<num clients> <number of ops> <request size> <write?> <measurement leader?>");
            System.exit(-1);
        }

        initialId = Integer.parseInt(args[0]);
        int numClients = Integer.parseInt(args[1]);
        int numOperations = Integer.parseInt(args[2]);
        int requestSize = Integer.parseInt(args[3]);
        boolean write = Boolean.parseBoolean(args[4]);
        boolean measurementLeader = Boolean.parseBoolean(args[5]);

        Client[] clients = new Client[numClients];
        Random random = new Random(1L);
        String key = "key";
        byte[] data = new byte[requestSize];
        random.nextBytes(data);
        byte[] writeRequest = serialize(Operation.PUT, key, data);
        byte[] readRequest = serialize(Operation.GET, key, null);

        for (int i = 0; i < numClients; i++) {
            clients[i] = new Client(initialId + i, writeRequest, readRequest,
                    numOperations, data, write, measurementLeader);
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

    private static byte[] serialize(Operation op, String str, byte[] data) {
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

    private static class Client extends Thread {
        private final int id;
        private final int numOperations;
        private final boolean write;
        private final ServiceProxy proxy;
        private final boolean measurementLeader;
        private int rampup = 1000;
        private final byte[] writeRequest;
        private final byte[] readRequest;
        private final byte[] data;

        Client(int id, byte[] writeRequest, byte[] readRequest, int numOperations,
               byte[] data, boolean write, boolean measurementLeader) {
            super("Client " + id);
            this.id = id;
            this.numOperations = numOperations;
            this.write = write;
            this.writeRequest = writeRequest;
            this.readRequest = readRequest;
            this.data = data;

            this.proxy = new ServiceProxy(id);
            this.measurementLeader = measurementLeader;
        }

        @Override
        public void run() {
            if (id == initialId) {
                if (measurementLeader)
                    System.out.println("I'm measurement leader");
                System.out.println("Sending test data...");
            }
            proxy.invokeOrdered(writeRequest, null, (byte) -1);
            byte[] response = proxy.invokeOrdered(readRequest, null, (byte) -1);
            if (!Arrays.equals(response, data)) {
                throw new RuntimeException("Wrong response");
            }
            try {
                if (id == initialId) {
                    System.out.println("Executing experiment for " + numOperations + " ops");
                }
                for (int i = 0; i < numOperations; i++) {
                    long t2;
                    long t1 = System.nanoTime();
                    if (write) {
                        proxy.invokeOrdered(writeRequest, null, (byte) -1);
                    } else {
                        proxy.invokeOrdered(readRequest, null, (byte) -1);
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
