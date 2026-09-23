import numpy as np
import matplotlib.pyplot as plt

flow = """flow data from data source, may need adjust below depending on data set"""

def moving_stats(data, window):
    data = np.asarray(data, dtype=float)

    windows = np.lib.stride_tricks.sliding_window_view(data, window)

    moving_avg = np.mean(windows, axis=1)
    moving_std = np.std(windows, axis=1)

    return moving_avg, moving_std


# 30-day moving example
window = 30

moving_avg, moving_std = moving_stats(flow, window)

# matploylib example output
for day, f, avg, std in zip(days, flow, moving_avg, moving_std):
    print(
        f"Day {day:3d}: "
        f"Flow = {f:7.2f}, "
        f"Moving Avg = {avg:7.2f}, "
        f"Moving Std = {std:6.2f}"
    )

plt.figure(figsize=(12, 6))

plt.plot(days, flow, color="lightgray", label="Daily Flow")
plt.plot(days, moving_avg, color="red", linewidth=2,
         label=f"{window}-Daily Moving Average")

plt.fill_between(
    days,
    moving_avg - moving_std,
    moving_avg + moving_std,
    color="lightgreen",
    alpha=0.2,
    label="±1 Moving Std. Dev."
)

plt.xlabel("Day of Year")
plt.ylabel("Flow")
plt.title("Daily Flow with Moving Average and Standard Deviation")
plt.legend()
plt.grid(alpha=0.3)
plt.tight_layout()
plt.show()
