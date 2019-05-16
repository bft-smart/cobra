import matplotlib.pyplot as plt
import sys


def load_log_file(filename):
    lines = []

    with open(filename) as log_file:
        for line in log_file:
            if "ops/sec" in line and "READ" in line and "UPDATE" in line:
                lines.append(line)
    return lines


def plot_throughput(lines):
    throughput = []

    for line in lines:
        value = line.split(";")[1].split()[0].replace(",", ".")
        throughput.append(float(value))

    return throughput


def plot_read_latency(lines):
    latency = []
    for line in lines:
        value = line.split(";")[2].split()[1].split("=")[1].split("]")[0].replace(",", ".")
        latency.append(float(value))
    return latency


def plot_update_latency(lines):
    latency = []
    for line in lines:
        value = line.split(";")[2].split()[3].split("=")[1].split("]")[0].replace(",", ".")
        latency.append(float(value))
    return latency


if len(sys.argv) != 3:
    print("Usage: <title> <log file>")
    exit(-1)

logFile = sys.argv[2]
title = sys.argv[1]
print("Reading log file ", logFile)

log = load_log_file(logFile)
throughput_values = plot_throughput(log)
read_latency = plot_read_latency(log)
update_latency = plot_update_latency(log)

graph_n_rows = 2
graph_n_cols = 1

plt.suptitle(title)
plt.subplot(graph_n_rows, graph_n_cols, 1)
plt.plot(throughput_values)
plt.title("Throughput")
plt.ylabel("Throughput (ops/sec)")

plt.subplot(graph_n_rows, graph_n_cols, 2)
plt.plot(update_latency, "r", label="Update")
plt.plot(read_latency, "g", label="Read")
plt.title("Latency")
plt.ylabel("Latency (us)")

plt.legend()

plt.show()
