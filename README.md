# COBRA - A COnfidential Byzantine ReplicAtion SMR library

COBRA is a fully-featured state machine replication library that guarantees the confidentiality of the data. 
Confidentiality is ensured by integrating a secret sharing mechanism into the 
modified [BFT-SMaRt](https://github.com/bft-smart/library) library, a fully-featured replication library without 
confidentiality guarantees. You can find the modified version of the BFT-SMaRt library [here](https://github.com/rvassantlal/library).

## Limitations
This library is a proof-of-concept implementation and not a production-ready implementation. 
Therefore, before using it, consider the following limitations:
* The periodic execution of the resharing protocol is disabled. It can be activated but requires hardcoding 
the number of shares to reshare;
* The constant commitment scheme, i.e., Kate et al.'s protocol, was not tested with recent changes;
* The adversarial attack for resharing is hardcoded in branches 
*[adversarial_1_faulty_servers](https://github.com/rvassantlal/COBRA/tree/adversarial_1_faulty_servers)*, 
*[adversarial_2_faulty_servers](https://github.com/rvassantlal/COBRA/tree/adversarial_2_faulty_servers)*, and 
*[adversarial_3_faulty_servers](https://github.com/rvassantlal/COBRA/tree/adversarial_3_faulty_servers)*;
* Recovery and resharing while changing the leader was not tested.

## Requirements
The COBRA library is primarily implemented in Java and currently uses Gradle to compile, package, and 
deploy compiled code for local testing. Nevertheless, we use C to implement the constant commitment scheme 
functions and call those functions in Java through Java Native Interface.

The current COBRA library was tested using Java 11.0.13.

## Compilation and Packaging
First, clone this repository. Now inside the `COBRA` folder (assuming you did not change the name), follow 
the following instructions depending on the intended result.

There are two ways to compile and package the COBRA library:
* Compile and package the library: Execute `./gradlew installDist`. The required jar files and default 
configurations files will be available inside the `build/install/COBRA` folder.
* Compile and package to locally test the library: Execute `./gradlew localDeploy`. The execution of Gradle 
task `localDeploy` will create the folder `build/local` containing `nServers` folders `rep*` and `nClients` 
folders `cli*` (you can change these parameters in the `build.gradle` file). Each server and client folder 
will have the required files to run COBRA demos.

To use the constant commitment scheme, follow the instructions presented in the 
Verifiable Secret Sharing library [repository](https://github.com/rvassantlal/VerifiableSecretSharing) to compile 
the required C code.

## Usage
Since COBRA extends the BFT-SMaRt library, first configure BFT-SMaRt following instructions presented in 
its [repository](https://github.com/bft-smart/library). Then configure COBRA's behaviour by modifying the 
`config/cobra.config` file.


**TIP:** Reconfigure the system before compiling and packaging. This way, you don't have to configure multiple replicas.

**NOTE:** Following commands considers the Linux operating system. For the Windows operating system, 
use script `run.cmd` instead of `./smartrun.sh`.

***Running the map demo (4 replicas tolerating 1 fault):***

Execute the following commands across four different server consoles from within 
the folders `build/local/rep*`:
```
build/local/rep0$./smartrun.sh confidential.demo.map.server.Server 0
build/local/rep1$./smartrun.sh confidential.demo.map.server.Server 1
build/local/rep2$./smartrun.sh confidential.demo.map.server.Server 2
build/local/rep3$./smartrun.sh confidential.demo.map.server.Server 3
```

Once all replicas are ready, the client can be launched by executing the following command in 
directory `build/local/cli0/`:
```
build/local/cli0$./smartrun.sh confidential.demo.map.client.Client 100
```

***Running throughput and latency experiment:***

After compiling and packaging, copy the content of the `COBRA/build/install/COBRA` folder into
different locations/servers. Next, we present an example of running a system with four replicas
tolerating one fault.

Execute the following commands across four different server consoles:
```
./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 0
./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 1
./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 2
./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 3
```

Once all replicas are ready, you can launch clients by executing the following command:
```
./smartrun.sh confidential.benchmark.PreComputedKVStoreClient <initial client id> <num clients> <number of ops> <request size> <write?> <precomputed?> <measurement leader?>
```
where:
* `<initial client id>` - the initial client id, e.g, 100;
* `<num clients>` - the number clients each execution of command will create, e.g., 20;
* `<number of ops>` - the number of requests each client will send, e.g., 10000;
* `<request size>` - the size in byte of each request, e.g., 1024;
* `<write?>` - requests are of write or read type? E.g., true;
* `<precompute?>` - are the requests precompute before sending to servers or are created on fly? E.g., true;
* `<measurement leader?>` - will this client print the latencies? E.g., true.

***Interpreting the throughput and latency results***

When clients continuously send the requests, servers will print the throughput information
every two seconds.
When a client finishes sending the requests, it will print a string containing space-separated
latencies of each request in nanoseconds. For example, you can use this result to compute average latency.


## Adversarial demonstration
Branches *[adversarial_1_faulty_servers](https://github.com/rvassantlal/COBRA/tree/adversarial_1_faulty_servers)*, 
*[adversarial_2_faulty_servers](https://github.com/rvassantlal/COBRA/tree/adversarial_2_faulty_servers)*, and 
*[adversarial_3_faulty_servers](https://github.com/rvassantlal/COBRA/tree/adversarial_3_faulty_servers)*
have hardcoded demonstration of the effect of 1, 2, and 3 faulty servers, respectively, during resharing 
in a system with ten replicas tolerating three faults.


In all demonstrations, replica 1 acts maliciously during resharing and send an invalid resharing polynomial proposal 
to replica 2. When this happens, replica 2 will receive an invalid share on the de-blinding polynomial needed to 
reconstruct its renewed share. Replica 2 starts executing the recovery protocol to recover its valid share.

During the execution of the recovery protocol, replica 1 sends an invalid recovery polynomial proposal to replica 3, 
which jeopardizes the recovery. Servers collectively remove replica 1, and replica 2 successfully recovers its share 
during the second execution of the recovery protocol. This scenario is demonstrated in the branch `adversarial_1_faulty_servers`.

In the scenario of a branch `adversarial_2_faulty_servers`, replica 4 sends an invalid recovery polynomial proposal 
to replica 3, which compromise the second recovery attempt. Again, after the remaining servers collectively remove 
replica 4, replica 2 successfully recovers its share during the third attempt.

Finally, in the third branch, `adversarial_3_faulty_servers`, replica 5 compromise the third recovery attempt, 
which is also removed by the servers. During the fourth recovery attempt, replica 2 successfully recovers its share on 
resharing polynomial.

You can test these demonstrations by following these instructions:
1) Clone the repository from the respective branch;
2) Start replicas by executing the following commands in consoles opened in each of `build/local/rep*` folder:
    ```
    build/local/rep0$./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 0
    build/local/rep1$./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 1
    build/local/rep2$./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 2
    build/local/rep3$./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 3
    build/local/rep4$./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 4
    build/local/rep5$./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 5
    build/local/rep6$./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 6
    build/local/rep7$./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 7
    build/local/rep8$./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 8
    build/local/rep9$./smartrun.sh confidential.benchmark.ThroughputLatencyKVStoreServer 9
    ```
3) Once all the replicas are ready, execute the following command inside the folder `build/local/cli0/`:
    ```
    build/local/cli0$./smartrun.sh confidential.benchmark.PreComputedKVStoreClient 100 1 1 1024 true true false
    ```
4) When the previous client terminates, execute the following command inside the folder `build/local/cli0/`:
   ```
   build/local/cli0$./smartrun.sh confidential.reconfiguration.ReconfigurationClient 7002 config/reconfiguration_f_3.json
    ```

The last step (Step 4) execution will trigger resharing protocols in servers. Depending on the branch, 
replica 2 will end resharing its state after the second, third, or fourth recovery attempt and will show 
the total resharing cost in milliseconds of resharing shares of one secret. To observe the positive impact of 
our protocol when resharing multiple secret shares with the influence of an adversary, in Step 3 execute:
```
build/local/cli0$./smartrun.sh confidential.benchmark.PreComputedKVStoreClient 100 1 1000 1024 true true false
```

## Changes to BFT-SMaRt
Following are the relevant modifications done in BFT-SMaRt:
* Invoking ordered and unordered operations with distinct public and private parts of requests;
* Temporarily storing private state (i.e., shares) in `ClientData` during the consensus execution;
* Checking proposed value during the consensus execution;
* Added a metadata field inside `MessageContext` and `TOMMessage`;
* Added a reconfiguration listener.

## Publication
The COBRA library results from research to improve secret sharing protocols while devising a practical 
replication library with confidentiality. The result was published at a conference that you can find here. 
The paper explains how the COBRA secret sharing protocols work.


***Feel free to contact us if you have any questions!***
