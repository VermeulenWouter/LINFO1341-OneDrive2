import matplotlib.pyplot as plt
import numpy as np
import pyshark

def analyse_protocols(capture_file):
    dict = {}
    cap = pyshark.FileCapture(input_file=capture_file, keep_packets=True)
    i = 0
    for packet in cap:
        if packet.highest_layer not in dict:
            dict[packet.highest_layer] = 0
        dict[packet.highest_layer] += 1
        if i % 1000 == 0:
            print(i)
        i += 1

    values = dict.values()
    sum_ = 0
    for val in values:
        sum_ += val
    other = 0
    to_del = []
    for key, value in dict.items():
        if value / sum_ < 0.01:
            other += value
            to_del.append(key)
    for elem in to_del:
        del dict[elem]

    dict["Autres"] = other
    order = ["QUIC", "TLS", "DNS", "TCP", "Autres"]
    return [dict[key] for key in order], order


def generate_pie_chart_with_percent_outside(ax, values, keys, title=None, *, no_legend: bool = False, angle: int = 0):
    """

    The keys are in a legend

    :param plot:
    :param values:
    :param keys:
    :return:


    Source: inspired by https://stackoverflow.com/questions/70200626/preventing-overlapping-labels-in-a-pie-chart-python-matplotlib
    """

    n_values = len(values)
    if n_values != len(keys):
        raise AttributeError  # TODO

    kw = dict(xycoords='data', textcoords='data', arrowprops=dict(arrowstyle='-'), zorder=0, va='center')

    values_array = np.array([float(value) for value in values], dtype=float)
    total = np.sum(values_array)
    percents = values_array / total * 100
    percent_labels = [f"{percent:.1f}%" for percent in percents]

    wedges, texts = ax.pie(values, startangle=angle, explode=[0.01 for _ in range(len(values))], radius=1)

    for i, p in enumerate(wedges):
        ang = (p.theta2 - p.theta1) / 2. + p.theta1
        y = np.sin(np.deg2rad(ang))
        x = np.cos(np.deg2rad(ang))
        horizontalalignment = {-1: "right", 1: "left"}[int(np.sign(x))]
        connectionstyle = f"angle,angleA=0,angleB={ang}"
        kw["arrowprops"].update({"connectionstyle": connectionstyle})
        ax.annotate(percent_labels[i], xy=(x, y), xytext=(1.35 * np.sign(x), 1.4 * y), horizontalalignment=horizontalalignment, **kw)

    ax.title.set_text(title)

    if not no_legend:
        ax.legend(title=title, labels=keys, loc="lower left")


def generate_double_pie_chart_with_percent_outside(plot, values1, keys1, title1, values2, keys2, title2, legend_title):
    """

    The keys are in a legend

    :param plot:
    :param values:
    :param keys:
    :return:


    Source: inspired by https://stackoverflow.com/questions/70200626/preventing-overlapping-labels-in-a-pie-chart-python-matplotlib
    """

    n_values1 = len(values1)
    if n_values1 != len(keys1):
        raise AttributeError  # TODO

    n_values2 = len(values2)
    if n_values2 != len(keys2):
        raise AttributeError  # TODO

    fig, (ax1, ax2) = plot.subplots(1, 2)
    plot.subplots_adjust(wspace=1.65, top=1, bottom=0)
    generate_pie_chart_with_percent_outside(ax1, values1, keys1, title1, no_legend=True, angle=-90)
    generate_pie_chart_with_percent_outside(ax2, values2, keys2, title2, no_legend=True, angle=-80)

    fig.legend(title=legend_title, labels=keys, loc="center")


#values, keys = analyse_protocols("./graph.pcap")
#print(values, keys)
values = [247, 3453, 688, 10791, 100]
keys   = ['QUIC', 'TLS', 'DNS', 'TCP', 'Autres']
#values1, keys1 = analyse_protocols("./graph_uclouvain.pcap")
#print(values1, keys1)
values1 = [20381, 4902, 683, 14873, 65]
keys1 = ['QUIC', 'TLS', 'DNS', 'TCP', 'Autres']
generate_double_pie_chart_with_percent_outside(plt, values, keys, "OneDrive Personal", values1, keys1, "OneDrive UCLouvain", "Protocoles")
plt.savefig("../Rapport/pictures/pie_chart.pdf", dpi=500, bbox_inches="tight")
plt.show()