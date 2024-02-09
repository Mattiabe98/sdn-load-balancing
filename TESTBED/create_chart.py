import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os

folder = "/home/ryu/ryu/ryu/app/"

def check_files_exist(file1_path, file2_path):
    if os.path.isfile(file1_path) and os.path.isfile(file2_path):
        return True
    else:
        return False


# function that creates the plot of average link bandwidth utilization over time
# as Sebastian said we can plot the chart with the load balancer off and then on and observe the difference
def create_avg_bw_util_chart():

    filename = 'Measurements/avg_utilization_lab.csv'
    avg_bw = pd.read_csv(folder+'Measurements/avg_utilization_lab.csv')

    x = avg_bw.iloc[:, 0]
    y = avg_bw.iloc[:, 1]
    # fitting the measurement points as a polynomial of degree n to avoid "fake" measurements
    coefficients = np.polyfit(x, y, 10)

    y_plot = np.polyval(coefficients, x)
    df = pd.read_csv(filename)
    avg_weight = df.iloc[:, 1]  # second column contains the average utilization value for each associated time instant

    meas_time = df.iloc[:, 0]

    fig_off = plt.figure(figsize=(20, 10))
    plt.plot(meas_time, avg_weight, color='b', label='BW utilization')
    plt.plot(meas_time, y_plot, color='red', label='Fitted curve', linewidth=3)

    plt.axhline(y=0.7, color='g', label='Threshold (70%)', linestyle=':')
    plt.axvline(x=40, color='black', linestyle='--', label='Load Balancer ON')

    plt.xlabel("time [s]")
    plt.ylabel("Avg percentage of bw utilization")
    plt.legend()
    fig_off.savefig(folder + 'Plots/MyAvgBwChart_lab.png', dpi=300)
    plt.close()

    print("AVG BW UTILIZATION CHART SAVED!")


create_avg_bw_util_chart()


