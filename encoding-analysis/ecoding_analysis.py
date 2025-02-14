import math
import numpy as np
import matplotlib.pyplot as plt

# Parameter für die Berechnung
n_values = range(5, 11)  # Werte für n (Anzahl der Cipher Suites)
k_values = range(1, 6)  # Werte für k (Anzahl der Verbindungen pro Übertragung)

# Matrix für ASCII-Zeichen pro Übertragung
ascii_matrix = np.zeros((len(n_values), len(k_values)))

# Berechnung der möglichen ASCII-Zeichen pro Kombination von n und k
for i, n in enumerate(n_values):
    n_fact = math.factorial(n)  # Berechne n!
    for j, k in enumerate(k_values):
        total_combinations = (n_fact) ** k  # (n!)^k
        bit_capacity = math.log2(total_combinations)  # Anzahl der Bits
        ascii_chars = bit_capacity / 8  # ASCII-Zeichen (8 Bit pro Zeichen)
        ascii_matrix[i, j] = ascii_chars

# Visualisierung
fig, ax = plt.subplots(figsize=(10, 6))

for i, n in enumerate(n_values):
    ax.plot(k_values, ascii_matrix[i, :], marker="o", label=f"{n} Cipher Suites")

ax.set_xlabel("Anzahl der Verbindungen (k)")
ax.set_ylabel("Maximale ASCII-Zeichen pro Übertragung")
ax.set_title("Optimierung von Cipher Suites (n) und Verbindungen (k)")
ax.legend(title="Cipher Suites (n)")
ax.grid(True)
ax.set_xticks(k_values)  # X-Achse nur in 1er-Schritten

# Diagramm speichern
plt.savefig("tls_cipher_suite_analysis.png")

# Optional: Diagramm anzeigen
plt.show()
