import matplotlib.pyplot as plt
import sys


def load_log_file(filename):
    lines = []

    with open(filename) as log_file:
        for line in log_file:
            if "ops/sec" in line and ("UPDATE" in line or "READ" in line):
                lines.append(line)
    return lines

def extract_values(lines):
    throughput = []
    read_latency = []
    update_latency = []

    update = "[UPDATE" in lines[0].split(";")[2].split()
    read = "[READ" in lines[0].split(";")[2].split()

    if update:
        print ("Log has update latency")

    if read:
        print ("Log has read latency")

    for line in lines:
        sep_values = line.split(";")
        t_value = sep_values[1].split()[0].replace(",", ".")
        throughput.append(float(t_value))
        latency = sep_values[2].split()
        if read:
            index = latency.index("[READ")
            r_value = latency[index + 1].split("=")[1].split("]")[0].replace(",", ".")
            read_latency.append(float(r_value))
        if update:
            index = latency.index("[UPDATE")
            u_value = latency[index + 1].split("=")[1].split("]")[0].replace(",", ".")
            update_latency.append(float(u_value))

    return throughput, read_latency, update_latency


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: <title> <log file>")
        exit(-1)

    logFile = sys.argv[2]
    title = sys.argv[1]
    print("Reading log file ", logFile)

    log = load_log_file(logFile)

    throughput_values, read_latency, update_latency = extract_values(log)

    graph_n_rows = 2
    graph_n_cols = 1

    plt.suptitle(title)
    plt.subplot(graph_n_rows, graph_n_cols, 1)
    plt.plot(throughput_values)
    plt.title("Throughput")
    plt.ylabel("Throughput (ops/sec)")

    plt.subplot(graph_n_rows, graph_n_cols, 2)
    if update_latency:
        plt.plot(update_latency, "r", label="Update")
    if read_latency:
        plt.plot(read_latency, "g", label="Read")
    plt.title("Latency")
    plt.ylabel("Latency (us)")

    plt.legend()

    plt.show()
