import math
import numpy as np
import matplotlib.pyplot as plt

# Parameters
n_values = range(5, 9)  # n (Number of Cipher Suites)
k_values = range(2, 9)  # k (Number of TLS Connections)

# Matrix for ASCII-chars per connection
ascii_matrix = np.zeros((len(n_values), len(k_values)))

# Calc of possible ASCII-chars per combination (sum of all smaller factorials)
for i, n in enumerate(n_values):
    total_factorial_sum = sum(math.factorial(r) for r in range(1, n + 1))  # Sum of factorials
    for j, k in enumerate(k_values):
        total_combinations = (total_factorial_sum) ** k  # (Sum of factorials)^k
        bit_capacity = math.log2(total_combinations)
        ascii_chars = bit_capacity / 8  # ASCII-chars (8-bit per char)
        ascii_matrix[i, j] = ascii_chars

# Visualization
fig, ax = plt.subplots(figsize=(10, 10))

for i, n in enumerate(n_values):
    ax.plot(k_values, ascii_matrix[i, :], marker="o", label=f"{n} Cipher Suites (Sum 1! to {n}!)")

    # Annotate each data point with the y-value
    for j, k in enumerate(k_values):
        ax.text(k, ascii_matrix[i, j], f"{ascii_matrix[i, j]:.2f}", 
                ha='center', va='bottom', fontsize=9)

ax.set_xlabel("TLS Connections (k)")
ax.set_ylabel("Maximum Number of 8-Bit ASCII Values")
ax.set_title("Analysis of Encoded 8-Bit ASCII Values - Permutations with Sum of Factorials (n)")
ax.legend(title="Cipher Suites (n)")
ax.grid(True)
ax.set_xticks(k_values)

# Set y-axis ticks dynamically based on max value
y_ticks = np.arange(0, np.max(ascii_matrix) + 1, 1)
ax.set_yticks(y_ticks)

# Adjust layout to crop extra margins
plt.tight_layout()
plt.subplots_adjust(left=0.12, right=0.95, top=0.90, bottom=0.12)

# Save cropped diagram
plt.savefig("encoding_analysis_permutations_non_fixed.svg", bbox_inches='tight', pad_inches=0.05)

# Show cropped diagram
plt.show()
