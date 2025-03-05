# Permutations Generator

This Python script generates JSON files containing permutations of specified elements with corresponding ASCII values. It supports various configuration options to customize the output according to your needs.

## Features

- Generate permutations from a list of elements
- Option to generate all subset permutations or only full permutations
- Configurable ASCII value dimensions (1D, 2D, or 3D)
- Support for extra entries beyond the ASCII value limits
- Customizable number of permutation groups per entry
- Lexicographical sorting of permutations

## Requirements

- Python 3.6 or higher
- Standard libraries only (no external dependencies)

## Installation

Simply download the `permutations_generator.py` file to your local machine.

## Usage

### Basic Usage

```bash
python permutations_generator.py
```

This will generate a file named `permutations.json` with default settings.

### Command Line Arguments

The script supports several command line arguments to customize the output:

| Argument | Description | Default |
|----------|-------------|---------|
| `--output` | Output file name | `permutations.json` |
| `--elements` | Comma-separated list of elements | `c1,c2,c3,c4,c5` |
| `--cumulative` | Generate all subset permutations (flag) | `False` |
| `--ascii-dim` | Number of ASCII dimensions (1, 2, or 3) | `2` |
| `--extra` | Number of extra entries to add beyond ASCII limit | `0` |
| `--groups` | Number of permutation groups in each entry | `2` |

### Examples

#### Generate with custom elements and output file

```bash
python permutations_generator.py --output custom_permutations.json --elements a,b,c,d
```

#### Generate all subset permutations

```bash
python permutations_generator.py --cumulative
```

#### Generate with 3D ASCII values and 10 extra entries

```bash
python permutations_generator.py --ascii-dim 3 --extra 10
```

#### Generate with 3 permutation groups per entry

```bash
python permutations_generator.py --groups 3
```

## Output Format

The script generates a JSON file with the following structure:

```json
[
  {
    "ID": 1,
    "Permutation": [["c1"], ["c1"]],
    "ASCII": [0, 0]
  },
  {
    "ID": 2,
    "Permutation": [["c1"], ["c2"]],
    "ASCII": [0, 1]
  },
  ...
]
```

Each entry consists of:
- `ID`: Sequential identifier starting from 1
- `Permutation`: List of permutation groups
- `ASCII`: ASCII values corresponding to the entry's ID

## ASCII Value Calculation

The ASCII values are calculated based on the entry's ID:

- For 1D ASCII: Values range from 0 to 255, with extra entries starting at 256
- For 2D ASCII: Values are represented as [ID//256, ID%256], with extra entries starting at [256, 0] and incrementing
- For 3D ASCII: Values are represented as [ID//(256²), (ID%256²)//256, ID%256], with extra entries starting at [256, 0, 0] and incrementing

## Extended Range Entries

For entries beyond the standard ASCII value limits:
- The script adds entries with incrementing values starting from 256
- In multi-dimensional ASCII configurations, only the first value increments while others remain at 0

## Using as a Module

You can also import and use the script as a module in your Python code:

```python
from permutations_generator import generate_permutations_file

generate_permutations_file(
    output_file="custom_output.json",
    elements=["a", "b", "c"],
    cumulative=True,
    ascii_dimensions=2,
    extra_entries=5,
    group_count=2
)
```

## Notes

- The maximum number of entries is limited by either the number of possible permutations or the ASCII limit plus any extra entries specified.
- The total number of possible permutation groups depends on the number of elements, whether cumulative mode is enabled, and the group count.

## Encoding Analysis

The repository includes two Python scripts for analyzing the encoding capacity of permutations:

### Standard Permutations Analysis

`encoding-analysis-permutations.py` analyzes the maximum number of 8-bit ASCII values that can be encoded using permutations with fixed length:

```bash
python encoding-analysis-permutations.py
```

This script:
- Calculates the encoding capacity for different combinations of cipher suites (n) and TLS connections (c)
- Uses the formula (n!)^c to calculate total possible combinations
- Converts bit capacity to equivalent ASCII characters
- Generates a visualization showing how many ASCII characters can be encoded with different parameters
- Outputs the results as an SVG file named `encoding_analysis_permutations.svg`

### Cumulative Permutations Analysis

`encoding-analysis-permutations-cumulative.py` analyzes encoding capacity when using all subset permutations:

```bash
python encoding-analysis-permutations-cumulative.py
```

This script:
- Calculates encoding capacity using the sum of all permutations of different lengths
- Uses the formula (sum of permutations)^c for total possible combinations
- Visualizes how many ASCII characters can be encoded with cumulative permutations
- Outputs the results as an SVG file named `encoding_analysis_permutations_cumulative.svg`

Both analyses help determine optimal parameters for maximizing encoding capacity while maintaining practical implementation constraints.