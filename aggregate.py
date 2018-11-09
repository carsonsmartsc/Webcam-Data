dirs = {
    "Brute_Force": 0,
    "Enterprise_Diligent": 1,
    "Enterprise_Lazy": 1,
    "Enterprise_Normal": 1,
    "Home_Vacation": 1,
    "Home_Weekday": 1,
    "Home_Weekend": 1,
    "Hping3": 0,
    "Infrastructure": 1,
    "Large_Ping": 0,
    "Ping_Flood": 0,
    "Scanning": 0
}

output_file = open("aggregated_data.txt", "w")

# Processes
for dir in dirs:
    for run in range(1, 4):
        traffic_type = "Attack" if dirs[dir] == 0 else "Normal"

        ps_file = open(dir + "/run" + str(run) + "/ps_data_webcam.txt")

        num_captures = 0
        num_processes = 0
        for line in ps_file:
            if "PID USER" in line:
                num_captures += 1
            if not line.split()[2] == "VSZ" and not line.split()[2] == "0":
                num_processes += 1
        avg_processes = num_processes / num_captures
        output_file.write(dir + " Run " + str(run) + ",")
        output_file.write(traffic_type + ",")
        output_file.write("# Running Processes,")
        output_file.write(str(avg_processes) + "\n")
output_file.write("\n")
print("Processes Done")

# Mem Usage
for dir in dirs:
    for run in range(1, 4):
        traffic_type = "Attack" if dirs[dir] == 0 else "Normal"

        top_file = open(dir + "/run" + str(run) + "/top_data_webcam.txt")

        num_captures = 0
        data_used = 0
        data_free = 0
        for line in top_file:
            if "Mem: " in line:
                num_captures += 1
                data_used += int(line.split()[1][:-1])
                data_free += int(line.split()[3][:-1])
        avg_data = 100 * data_used / (data_used + data_free)
        output_file.write(dir + " Run " + str(run) + ",")
        output_file.write(traffic_type + ",")
        output_file.write("% Memory Used,")
        output_file.write(str(avg_data) + "\n")
output_file.write("\n")
print("Mem Done")

# Usr CPU Usage
for dir in dirs:
    for run in range(1, 4):
        traffic_type = "Attack" if dirs[dir] == 0 else "Normal"

        top_file = open(dir + "/run" + str(run) + "/top_data_webcam.txt")

        num_captures = 0
        cpu_usr = 0
        for line in top_file:
            if "Mem: " in line:
                num_captures += 1
            if "CPU: " in line:
                cpu_usr += float(line.split()[1][:-1])
        avg_usr = cpu_usr / num_captures
        output_file.write(dir + " Run " + str(run) + ",")
        output_file.write(traffic_type + ",")
        output_file.write("% Usr CPU Usage,")
        output_file.write(str(avg_usr) + "\n")
output_file.write("\n")
print("Usr CPU Done")

# Sys CPU Usage
for dir in dirs:
    for run in range(1, 4):
        traffic_type = "Attack" if dirs[dir] == 0 else "Normal"

        top_file = open(dir + "/run" + str(run) + "/top_data_webcam.txt")

        num_captures = 0
        cpu_sys = 0
        for line in top_file:
            if "Mem: " in line:
                num_captures += 1
            if "CPU: " in line:
                cpu_sys += float(line.split()[3][:-1])
        avg_sys = cpu_sys / num_captures
        output_file.write(dir + " Run " + str(run) + ",")
        output_file.write(traffic_type + ",")
        output_file.write("% Sys CPU Usage,")
        output_file.write(str(avg_sys) + "\n")
output_file.write("\n")
print("Sys CPU Done")

# Idle CPU Usage
for dir in dirs:
    for run in range(1, 4):
        traffic_type = "Attack" if dirs[dir] == 0 else "Normal"

        top_file = open(dir + "/run" + str(run) + "/top_data_webcam.txt")

        num_captures = 0
        cpu_idle = 0
        for line in top_file:
            if "Mem: " in line:
                num_captures += 1
            if "CPU: " in line:
                cpu_idle += float(line.split()[7][:-1])
        avg_idle = cpu_idle / num_captures
        output_file.write(dir + " Run " + str(run) + ",")
        output_file.write(traffic_type + ",")
        output_file.write("% Idle CPU Usage,")
        output_file.write(str(avg_idle) + "\n")
output_file.write("\n")
print("Idle CPU Done")

# Connections
for dir in dirs:
    for run in range(1, 4):
        traffic_type = "Attack" if dirs[dir] == 0 else "Normal"

        netstat_file = open(dir + "/run" + str(run) + "/netstat_data_webcam.txt")

        num_captures = 0
        open_connections = 0
        for line in netstat_file:
            if "Active Internet" in line:
                num_captures += 1
            if "LISTEN" in line or "ESTABLISHED" in line:
                open_connections += 1
        avg_conn = open_connections / num_captures
        output_file.write(dir + " Run " + str(run) + ",")
        output_file.write(traffic_type + ",")
        output_file.write("# Open Connections,")
        output_file.write(str(avg_conn) + "\n")
output_file.write("\n")
print("Connections Done")

# Bytes Out Per Second
for dir in dirs:
    for run in range(1, 4):
        traffic_type = "Attack" if dirs[dir] == 0 else "Normal"

        wireshark_file = open(dir + "/run" + str(run) + "/wireshark_data_host.csv")

        bytes = 0
        initial_time = 0
        final_time = 0
        for line in wireshark_file:
            if line.split()[5] == "00:02:b2:0e:89:4c":
                bytes += int(line.split()[9])

                curr_time = 0
                a = line.split()[2]
                curr_time += 3600 * float(a[:a.index(":")])
                a = a[a.index(":") + 1:]
                curr_time += 60 * float(a[:a.index(":")])
                a = a[a.index(":") + 1:]
                curr_time += float(a)

                if initial_time == 0:
                    initial_time = curr_time
                if final_time < curr_time:
                    final_time = curr_time
        bytes_out = bytes / (final_time - initial_time)
        output_file.write(dir + " Run " + str(run) + ",")
        output_file.write(traffic_type + ",")
        output_file.write("# Bytes Out / s,")
        output_file.write(str(bytes_out) + "\n")
output_file.write("\n")
print("Bytes Out Done")

# Bytes In Per Second
for dir in dirs:
    for run in range(1, 4):
        traffic_type = "Attack" if dirs[dir] == 0 else "Normal"

        wireshark_file = open(dir + "/run" + str(run) + "/wireshark_data_host.csv")

        bytes = 0
        initial_time = 0
        final_time = 0
        for line in wireshark_file:
            if line.split()[7] == "00:02:b2:0e:89:4c":
                bytes += int(line.split()[9])

                curr_time = 0
                a = line.split()[2]
                curr_time += 3600 * float(a[:a.index(":")])
                a = a[a.index(":") + 1:]
                curr_time += 60 * float(a[:a.index(":")])
                a = a[a.index(":") + 1:]
                curr_time += float(a)

                if initial_time == 0:
                    initial_time = curr_time
                if final_time < curr_time:
                    final_time = curr_time
        bytes_in = bytes / (final_time - initial_time)
        output_file.write(dir + " Run " + str(run) + ",")
        output_file.write(traffic_type + ",")
        output_file.write("# Bytes In / s,")
        output_file.write(str(bytes_in) + "\n")
output_file.write("\n")
print("Bytes In Done")

# Protocols
for dir in dirs:
    for run in range(1, 4):
        traffic_type = "Attack" if dirs[dir] == 0 else "Normal"

        wireshark_file = open(dir + "/run" + str(run) + "/wireshark_data_host.csv")

        protocols = []
        protocol_count = 0
        for line in wireshark_file:
            if line.split()[8] not in protocols:
                protocols.append(line.split()[8])
                protocol_count += 1
        output_file.write(dir + " Run " + str(run) + ",")
        output_file.write(traffic_type + ",")
        output_file.write("# Protocols,")
        output_file.write(str(protocol_count) + "\n")
output_file.write("\n")
print("Protocols Done")
