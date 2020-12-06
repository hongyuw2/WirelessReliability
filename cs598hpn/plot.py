import matplotlib.pyplot as plt

loss_rates = ['0%', '1%', '3%', '5%', '7%', '10%']
completion_time_baseline = [9.09, 13.19, 16.92, 26.02, 31.43, 41.32]
completion_time_snoop = [10.13, 10.46, 11.20, 12.14, 13.34, 13.85]

bar1 = [i - 0.2 for i in range(len(loss_rates))]
bar2 = [i + 0.2 for i in range(len(loss_rates))]
plt.bar(bar1, completion_time_baseline, label='Baseline', width = 0.4)
plt.bar(bar2, completion_time_snoop, label='P4-Snoop', width = 0.4)
plt.xlabel('Loss Rate')
plt.ylabel('Flow Completion Time (s)')
plt.xticks(range(len(loss_rates)), loss_rates)
plt.legend()
plt.savefig('loss_rate_comparison.png')
plt.show()


cache_entries = ['1', '10', '50', '100']
completion_time = [25.89, 19.45, 15.35, 12.44]

plt.bar(cache_entries, completion_time, width = 0.7)
plt.xlabel('Number of Cache Entries')
plt.ylabel('Flow Completion Time (s)')
plt.savefig('cache_entry_comparison.png')
plt.show()
