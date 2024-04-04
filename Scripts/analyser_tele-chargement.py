import matplotlib.pyplot as plt
import numpy as np
import pyshark


IP_Personnel_chargement = ["13.107.42.12"]


def extract_data(path: str, ip, number_of_files):
    number_sent_TCP = []
    number_received_TCP = []
    data_volume_sent = []
    data_volume_received = []
    time = []

    for i in range(number_of_files):
        print(i)
        cap = pyshark.FileCapture(input_file=f"{path}_{2**i}B.pcap", keep_packets=True, display_filter="tcp && ip")
        sum_send = 0
        sum_received = 0
        send = 0
        received = 0
        min_time = 0
        max_time = 0
        initial_time = float(cap[0].sniff_timestamp)
        for packet in cap:
            sum_send += (packet.ip.dst in ip)
            send += (packet.ip.dst in ip) * int(packet.length)
            sum_received += (packet.ip.src in ip)
            received += (packet.ip.src in ip) * int(packet.length)
            if min_time == 0 and float(packet.sniff_timestamp) - initial_time > 4 : min_time = float(packet.sniff_timestamp)
            max_time = float(packet.sniff_timestamp)
        number_sent_TCP.append(sum_send)
        number_received_TCP.append(sum_received)
        data_volume_sent.append(send)
        data_volume_received.append(received)
        time.append(max_time - min_time)

        print(f"number_sent_tcp = {number_sent_TCP}")
        print(f"number_received_tcp = {number_received_TCP}")
        print(f"data_volume_sent = {data_volume_sent}")
        print(f"data_volume_received = {data_volume_received}")
        print(f"time = {time}")
        print("\n")

    return number_sent_TCP, number_received_TCP, data_volume_sent, data_volume_received


def plot_upload(packet_number_sent, packet_number_received, data_volume_sent, data_volume_received):
    fig = plt.figure()
    ax = fig.add_subplot()

    n = len(packet_number_sent)
    file_sizes = [2**i for i in range(n)]
    data_volume_sent = np.array(data_volume_sent) / 10240   # [10 Ko]
    data_volume_received = np.array(data_volume_received) / 10240   # [10 Ko]
    # data_volume_total = (np.array(data_volume_sent) + np.array(data_volume_received)) / 10240   # [10 Ko]

    ax.plot(file_sizes, packet_number_sent, "o", color="tab:blue", label="Nombre de paquets envoyés au serveur")
    ax.plot(file_sizes, packet_number_received, "o", color="tab:orange", label="Nombre de paquets reçus du serveur")
    ax.plot(file_sizes, packet_number_sent, ":", color="tab:blue")
    ax.plot(file_sizes, packet_number_received, ":", color="tab:orange")

    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=10)
    ax.set_xlim(xmin=1/2, xmax=2**n)
    ax.set_ylim(ymin=1)
    ax.set_xticks(ticks=[1, 2**3, 2**7, 2**11, 2**15, 2**19, 2**23, 2**27])
    ax.set_xticklabels(labels=["1", "8", "128", "2ko", "32ko", "512ko", "8Mo", "128Mo"])

    ax1 = ax.twiny()
    ax1.set_xscale("linear")
    ax1.bar([i for i in range(n)], data_volume_sent, alpha=0.7, label="Volume de données envoyés au serveur")
    ax1.bar([i for i in range(n)], data_volume_received, alpha=0.7, label="Volume de données reçus du serveur")
    ax1.set_xlim(xmin=-1, xmax=n)  # Now x-axis correspond with the axis of ax
    ax1.set_xticks([])
    ax1.set_yscale("log", base=10)

    ax.set_xlabel("Taille du fichier [octets]")
    ax.set_ylabel("Nombre de paquets [/]\nVolume de données [10 Ko]")
    ax.legend(loc="upper left")
    ax1.legend(loc="upper left", bbox_to_anchor=(0, 0.85))
    plt.title("Analyse du chargement d'un fichier avec compte personnel", loc="right")
    plt.savefig("upload_personnel.pdf")
    plt.show()


## number_sent_tcp, number_received_tcp, data_volume_sent, data_volume_received = extract_data("../TestsChargement/ComptePersonnel/upload", IP_Personnel_chargement, 27)
number_sent_tcp = [18, 15, 15, 14, 16, 19, 19, 18, 21, 23, 18, 18, 22, 21, 26, 31, 42, 63, 87, 151, 209, 272, 426, 822, 1271, 4026, 7772]
number_received_tcp = [18, 19, 13, 15, 21, 23, 26, 20, 23, 23, 21, 27, 24, 22, 36, 51, 48, 64, 104, 159, 268, 471, 918, 2793, 6201, 12096, 24702]
data_volume_sent     = [7224, 7587, 6890, 6968, 8221, 8580, 7435, 7626, 8230, 9249, 8661, 10515, 12782, 15609, 24363, 42172, 74991, 141777, 274404, 541512, 1071515, 2127273, 4238671, 8469500, 16908264, 33920750, 67789598]
data_volume_received = [5714, 6787, 6251, 6423, 7635, 9994, 8894, 10663, 11231, 11470, 12492, 10604, 12521, 11153, 12399, 15795, 16685, 15320, 18538, 22445, 32278, 47587, 79511, 205898, 442153, 849792, 1711898]
time = [14.319155931472778, 9.104968070983887, 18.070855855941772, 2.3349220752716064, 8.135289192199707, 14.112995862960815, 10.23191213607788, 7.490334987640381, 14.257843017578125, 4.12666392326355, 4.908231019973755, 6.04034686088562, 14.622546911239624, 11.416763067245483, 13.974004983901978, 5.682645082473755, 5.661221981048584, 15.155689001083374, 14.042078971862793, 13.873528003692627, 8.497155904769897, 5.770822048187256, 8.774502038955688, 9.844619989395142, 18.402969121932983, 49.55148792266846, 92.48411321640015]


sizes = [i**2 for i in range(27)]
plt.plot(sizes, data_volume_sent, "o", label="sent")
plt.plot(sizes, data_volume_received, "o", label="received")
plt.plot(sizes, number_sent_tcp, label="TCP sent")
plt.plot(sizes, number_received_tcp, label="TCP received")
plt.legend()
plt.show()


plot_upload(number_sent_tcp, number_received_tcp, data_volume_sent, data_volume_received)
