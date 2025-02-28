import math
import numpy as np
import matplotlib.pyplot as plt

# Parameter
n_values = range(5, 11)  # n (Number of Cipher Suites)
k_values = range(1, 11)  # k (Number of TLS Connections)

# Matrix for ASCII-chars per connection
ascii_matrix = np.zeros((len(n_values), len(k_values)))

# Calc of possible ASCII-chars per combination n to k
for i, n in enumerate(n_values):
    n_fact = math.factorial(n)
    for j, k in enumerate(k_values):
        total_combinations = (n_fact) ** k  # (n!)^k
        bit_capacity = math.log2(total_combinations)
        ascii_chars = bit_capacity / 8  # ASCII-chars (8 Bit per char)
        ascii_matrix[i, j] = ascii_chars

# Visualization
fig, ax = plt.subplots(figsize=(10, 10))

for i, n in enumerate(n_values):
    ax.plot(k_values, ascii_matrix[i, :], marker="o", label=f"{n} Cipher Suites")

    # Annotate each data point with the y-value
    for j, k in enumerate(k_values):
        ax.text(k, ascii_matrix[i, j], f"{ascii_matrix[i, j]:.2f}", 
                ha='center', va='bottom', fontsize=9)

ax.set_xlabel("TLS Connections (k)")
ax.set_ylabel("Maximum Number of 8-Bit ASCII Values")
ax.set_title("Analysis of Encoded 8-Bit ASCII Values - Permutations")
ax.legend(title="Cipher Suites (n)")
ax.grid(True)
ax.set_xticks(k_values)

# Set y-axis ticks in 0.1-step increments
y_ticks = np.arange(0, np.max(ascii_matrix) + 1, 1)
ax.set_yticks(y_ticks)

# Save diag
plt.savefig("encoding_analysis_permutations.png")

# Show diag
plt.show()
