import matplotlib.pyplot as plt
import numpy as np

# make data
x = np.linspace(0, 10, 100)
y = 4 + 2 * np.sin(2 * x)
y2 = 4 + 2 * np.sin(x)

# plot

fig, ax = plt.subplots()

ax.plot(x, y, linewidth=2.0, label="y1")
ax.plot(x, y2, linewidth=2.0, label="y2")
plt.xlabel("Time (s)")
plt.ylabel("Some Other Stuff")

ax.legend()

ax.set(xlim=(0, 8), xticks=np.arange(1, 8),
       ylim=(0, 8), yticks=np.arange(1, 8))

if __name__ == "__main__":
   plt.show()