import matplotlib.pyplot as plt
import sys


def load_log_file(filename):
    lines = []
    has_insert = False
    has_read = False
    with open(filename) as log_file:
        for line in log_file:
            has_insert |= "INSERT" in line
            has_read |= "READ" in line
            if "ops/sec" in line and ("INSERT" in line or "READ" in line):
                lines.append(line)
    return lines, has_insert, has_read


def extract_values(log_files):
    has_insert = False
    has_read = False
    logs = []
    min_time = 2 << 31
    max_time = 0

    num_records = 2 << 31

    for log_file in log_files:
        print("Reading log file ", log_file)
        log, insert, read = load_log_file(log_file)
        has_insert |= insert
        has_read |= read
        num_records = min(num_records, len(log))
        logs.append(log)

    if has_insert:
        print("Log has insert latency")

    if has_read:
        print("Log has read latency")

    log_values = {}

    for log in logs:
        values = {}
        for record in log:
            record_values = []
            sep_values = record.split(";")
            time = int(sep_values[0].split()[0])
            min_time = min(min_time, time)
            max_time = max(max_time, time)

            throughput = float(sep_values[1].split()[0].replace(",", "."))
            record_values.append(throughput)

            latency = sep_values[2].split()
            if has_insert:
                index = latency.index("[INSERT")
                insert = float(latency[index + 1].split("=")[1].split("]")[0].replace(",", "."))
                record_values.append(insert)
            if has_read:
                index = latency.index("[READ")
                read = float(latency[index + 1].split("=")[1].split("]")[0].replace(",", "."))
                record_values.append(read)
            values[time] = record_values
        for record in values:
            if record not in log_values:
                log_values[record] = values[record][:]
            else:
                old_values = log_values[record]
                current_values = values[record]
                latency = [(x + y) / 2.0 for x, y in zip(old_values, current_values)]
                new_values = [old_values[0] + current_values[0]]
                new_values.extend(latency[1:])
                log_values[record] = new_values
    throughputs = []
    insert_latency = []
    read_latency = []

    for t in range(min_time, max_time + 1):
        if t not in log_values:
            continue
        record = log_values[t]
        throughputs.append(record[0])
        if has_read and has_insert:
            read_latency.append(record[1])
            insert_latency.append(record[2])
        elif has_read:
            read_latency.append(record[1])
        elif has_insert:
            insert_latency.append(record[1])
    return throughputs, read_latency, insert_latency


def compute_avg(throughput, read_latency, update_latency):
    throughput_avg = sum(throughput) / len(throughput)
    read_avg = 0
    insert_avg = 0
    if read_latency:
        read_avg = sum(read_latency) / len(read_latency)
    if update_latency:
        insert_avg = sum(update_latency) / len(update_latency)
    print("Throughput avg:", throughput_avg, "ops/s")
    print("Read latency avg:", read_avg, "us")
    print("Insert latency avg:", insert_avg, "us")
    return throughput_avg, read_avg, insert_avg


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: <title> <log file> [<log file>]")
        exit(-1)

    title = sys.argv[1]

    throughput_values, read_latency, insert_latency = extract_values(sys.argv[2:])

    throughput_avg, read_avg, insert_avg = compute_avg(throughput_values, read_latency, insert_latency)

    graph_n_rows = 2
    graph_n_cols = 1

    plt.suptitle(title)
    plt.subplot(graph_n_rows, graph_n_cols, 1)
    plt.plot(throughput_values, "b", label="Throughput (avg: " + str(round(throughput_avg)) + " ops/s)")
    plt.hlines(throughput_avg, 0, 300, colors="b")
    plt.grid(linestyle='dotted')
    plt.title("Throughput")
    plt.ylabel("Throughput (ops/sec)")
    plt.legend()

    plt.subplot(graph_n_rows, graph_n_cols, 2)
    if insert_latency:
        plt.plot(insert_latency, "r", label="Insert (avg: " + str(round(insert_avg)) + " us)")
        plt.hlines(insert_avg, 0, 300, colors="r")
    if read_latency:
        plt.plot(read_latency, "g", label="Read (avg: " + str(round(read_avg)) + " us)")
        plt.hlines(read_avg, 0, 300, colors="g")
    plt.title("Latency")
    plt.ylabel("Latency (us)")
    plt.grid(linestyle='dotted')
    plt.legend()

    plt.show()
