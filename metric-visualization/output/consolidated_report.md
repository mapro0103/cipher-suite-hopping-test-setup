# TLS COVERT CHANNEL PERFORMANCE ANALYSIS

## 1. Bandwidth Analysis
| Data Type | Avg. Bandwidth (bits/s) | Min | Max | Median | Mean | Std Dev |
| --------- | ---------------------- | --- | --- | ------ | ---- | ------- |
| PASSWORD | 406.39 | 341.57 | 437.28 | 428.90 | 409.56 | 34.48 |
| RSA | 372.17 | 356.97 | 381.72 | 373.35 | 372.25 | 5.64 |
| ECC | 365.36 | 334.64 | 386.84 | 369.58 | 365.88 | 13.58 |

## 2. Covert-to-Overt Data Ratio
| Data Type | Covert:Overt Ratio (%) | Avg. Covert Data (kbits) | Avg. Overt Data (kbits) |
| --------- | --------------------- | ------------------------- | ------------------------ |
| PASSWORD | 0.3772% | 0.160 | 42.42 |
| RSA | 0.3772% | 25.955 | 6880.16 |
| ECC | 0.3769% | 1.824 | 483.95 |

## 3. Connection Efficiency
| Data Type | Avg. Connections Per Transmission | Total Connections |
| --------- | -------------------------------- | ----------------- |
| PASSWORD | 10.00 | 500 |
| RSA | 1622.16 | 81108 |
| ECC | 114.00 | 5700 |

## 4. Transmission Reliability
| Data Type | Perfect Transmission Rate | Bit-level Accuracy |
| --------- | ------------------------- | ----------------- |
| PASSWORD | 100.00% | 100.00% |
| RSA | 100.00% | 100.00% |
| ECC | 100.00% | 100.00% |