import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os
import sys

topology_number = sys.argv[1]   # pass from terminal the topology for the simulation
traffic = sys.argv[2]

if traffic != "iperf" and traffic != "itg":
    sys.exit()  # 2 argument MUST BE either itg or iperf

def check_files_exist(file1_path, file2_path):
    if os.path.isfile(file1_path) and os.path.isfile(file2_path):
        return True
    else:
        return False


# function that creates the plot of average link bandwidth utilization over time
# we can plot comparison between the two lines (load balancer on and off)
# n is the degree of polynomial used to fit the measurement points
def compare_charts(n=10):
    avg_bw_on = pd.read_csv('Measurements/'+str(traffic)+'/avg_utilization_lb_on_'+str(topology_number)+'.csv')
    avg_bw_off = pd.read_csv('Measurements/'+str(traffic)+'/avg_utilization_lb_off_'+str(topology_number)+'.csv')

    x_on, x_off = avg_bw_on.iloc[:, 0], avg_bw_off.iloc[:, 0]
    y_on, y_off = avg_bw_on.iloc[:, 1], avg_bw_off.iloc[:, 1]
    # fitting the measurement points as a polynomial of degree n to avoid "fake" measurements
    coefficients_on = np.polyfit(x_on, y_on, n)
    coefficients_off = np.polyfit(x_off, y_off, n)

    y_plot_on = np.polyval(coefficients_on, x_on)
    y_plot_off = np.polyval(coefficients_off, x_off)
    fig = plt.figure(figsize=(20, 10))
    plt.plot(x_on, y_plot_on, color='red', label='Fitted curve on', linewidth=3)
    plt.plot(x_off, y_plot_off, color='blue', label='Fitted curve off', linewidth=3)

    # fig = plt.figure(figsize=(20, 10))
    plt.plot(avg_bw_on.iloc[:, 0], avg_bw_on.iloc[:, 1], linestyle='dashed', linewidth=0.5, marker='o', color='red', markersize=2, label='Data Points on')
    plt.plot(avg_bw_off.iloc[:, 0], avg_bw_off.iloc[:, 1], linestyle='dashed', linewidth=0.5, marker='+', color='blue', markersize=2, label='Data Points off')

    plt.axhline(y=0.7, color='g', linestyle=':')

    plt.xlabel("time [s]")
    plt.ylabel("Avg percentage of bw utilization")
    plt.legend()

    fig.savefig('Plots/'+str(traffic)+'/Comparison_Chart_'+str(topology_number)+'.png', dpi=300)

    plt.close()
    print("COMPARISON CHART SAVED!")


if check_files_exist('Measurements/'+str(traffic)+'/avg_utilization_lb_on_'+str(topology_number)+'.csv', 'Measurements/'+str(traffic)+'/avg_utilization_lb_off_'+str(topology_number)+'.csv'):
    compare_charts()
else:
    print("Can't plot the comparison chart since some files are missed!")
