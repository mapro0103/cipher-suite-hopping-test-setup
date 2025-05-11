import math
import numpy as np
import matplotlib.pyplot as plt

# Set the default font size for all text elements
plt.rcParams.update({'font.size': 22})

# Parameter
n_values = range(5, 9)  # n (Number of Cipher Suites)
c_values = range(2, 6)  # c (Number of TLS Connections)

# Matrix for ASCII-chars per connection
ascii_matrix = np.zeros((len(n_values), len(c_values)))

# Calc of possible ASCII-chars per combination n to c
for i, n in enumerate(n_values):
    n_fact = math.factorial(n)
    for j, c in enumerate(c_values):
        total_combinations = (n_fact) ** c  # (n!)^c
        bit_capacity = math.log2(total_combinations)
        ascii_chars = bit_capacity / 8  # ASCII-chars (8 Bit per char)
        ascii_matrix[i, j] = ascii_chars

# Visualization
fig, ax = plt.subplots(figsize=(10, 10))

for i, n in enumerate(n_values):
    ax.plot(c_values, ascii_matrix[i, :], marker="o", label=f"{n} Cipher Suites")
    # Annotate each data point with the y-value
    for j, c in enumerate(c_values):
        ax.text(c, ascii_matrix[i, j], f"{ascii_matrix[i, j]:.2f}",
                ha='center', va='bottom', fontsize=22)
        
ax.set_xlabel("TLS Connections (c)", fontsize=26)
ax.set_ylabel("Maximum Number of 8-Bit ASCII Values", fontsize=26)
ax.set_title("Permutations with Fixed Length", fontsize=22, fontweight='bold')  # Increased from 14 to 16

# Set legend font size to 14
ax.legend(title="Cipher Suites (n)", fontsize=22, title_fontsize=22)

ax.grid(True)
ax.set_xticks(c_values)

# Set fixed y-axis from 0 to 11
ax.set_ylim(0, 11)

# Set y-axis ticks at regular intervals
ax.set_yticks(np.arange(0, 11.1, 1))

# Set tick label font sizes to 14
ax.tick_params(axis='both', which='major', labelsize=22)

# Adjust layout to crop extra margins

plt.tight_layout()  # Automatically crops whitespace
plt.subplots_adjust(left=0.12, right=0.95, top=0.90, bottom=0.12)  # Fine-tune spacing

# Save cropped diagram
plt.savefig("encoding_analysis_permutations.svg", bbox_inches='tight', pad_inches=0.05)
plt.savefig("encoding_analysis_permutations.png", bbox_inches='tight', pad_inches=0.05)
plt.savefig("encoding_analysis_permutations.pdf", bbox_inches='tight', pad_inches=0.05)

# Show cropped diagram
plt.show()