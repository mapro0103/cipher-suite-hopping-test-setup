import json
import itertools
import argparse

def generate_permutations_file(output_file="permutations_scenario2.json", 
                              elements=["c1", "c2", "c3", "c4", "c5"],
                              cumulative=True,
                              ascii_dimensions=2,
                              extra_entries=0,
                              group_count=2):
    """
    Generate a JSON file with permutations and their corresponding ASCII values.
    
    Args:
        output_file (str): Name of the output JSON file
        elements (list): Elements to generate permutations for
        cumulative (bool): If True, generate all subset permutations; if False, only full permutations
        ascii_dimensions (int): Number of ASCII values to include (1, 2, or 3)
        extra_entries (int): Number of additional entries to add beyond the ASCII limit
        group_count (int): Number of permutation groups in each entry (default: 2)
    """
    
    # Generate all possible subset permutations or only full permutations
    all_permutations = []
    
    if cumulative:
        # For each possible size of a subset
        for r in range(1, len(elements) + 1):
            # Generate all combinations of this size
            for subset in itertools.combinations(elements, r):
                # Generate all permutations of this combination
                for perm in itertools.permutations(subset):
                    all_permutations.append(list(perm))
    else:
        # Only generate full permutations of all elements
        for perm in itertools.permutations(elements):
            all_permutations.append(list(perm))
    
    # Sort lexicographically
    all_permutations.sort()
    
    # Generate all combinations of permutations based on group_count
    permutation_groups = list(itertools.product(all_permutations, repeat=group_count))
    
    # Sort by lexicographical order
    permutation_groups.sort()
    
    # Map to ASCII values
    entries = []
    
    # Number of unique ASCII value combinations
    if ascii_dimensions == 1:
        max_ascii_entries = 256
    elif ascii_dimensions == 2:
        max_ascii_entries = 256 * 256
    else:  # ascii_dimensions == 3
        max_ascii_entries = 256 * 256 * 256
    
    # Calculate total entries to generate (ASCII limit + extra)
    total_entries = min(len(permutation_groups), max_ascii_entries + extra_entries)
    
    # Generate entries with ASCII values
    for idx, perm_group in enumerate(permutation_groups[:total_entries], 1):  # Start ID from 1
        if idx <= max_ascii_entries:
            if ascii_dimensions == 1:
                ascii_values = [idx - 1]  # Adjust for 0-based ASCII values
            elif ascii_dimensions == 2:
                ascii_values = [(idx - 1) // 256, (idx - 1) % 256]
            else:  # ascii_dimensions == 3
                idx_0 = (idx - 1) // (256 * 256)
                idx_1 = ((idx - 1) % (256 * 256)) // 256
                idx_2 = (idx - 1) % 256
                ascii_values = [idx_0, idx_1, idx_2]
        else:
            # For extra entries beyond ASCII limit, use the last valid ASCII value
            if ascii_dimensions == 1:
                ascii_values = [256]
            elif ascii_dimensions == 2:
                ascii_values = [256, 256]
            else:  # ascii_dimensions == 3
                ascii_values = [256, 256, 256]
                
        entry = {
            "ID": idx,
            "Permutation": list(perm_group),  # Convert tuple of permutations to list
            "ASCII": ascii_values
        }
        entries.append(entry)
    
    # Write to JSON file
    with open(output_file, 'w') as f:
        json.dump(entries, f, indent=2)
    
    print(f"File '{output_file}' created with {len(entries)} entries.")
    print(f"Total possible permutation groups: {len(permutation_groups)}")
    print(f"ASCII limit: {max_ascii_entries}, Extra entries: {extra_entries}")
    print(f"ID range: 1 to {total_entries}")
    print(f"Group count per entry: {group_count}")
    print(f"ASCII dimensions: {ascii_dimensions}")

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Generate permutations JSON file')
    parser.add_argument('--output', type=str, default='permutations_scenario2.json', 
                        help='Output file name')
    parser.add_argument('--elements', type=str, default='c1,c2,c3,c4,c5', 
                        help='Comma-separated list of elements')
    parser.add_argument('--cumulative', action='store_true', 
                        help='Generate all subset permutations')
    parser.add_argument('--ascii-dim', type=int, choices=[1, 2, 3], default=2, 
                        help='Number of ASCII dimensions (1, 2, or 3)')
    parser.add_argument('--extra', type=int, default=0, 
                        help='Number of extra entries to add beyond ASCII limit')
    parser.add_argument('--groups', type=int, default=2, 
                        help='Number of permutation groups in each entry (default: 2)')
    
    args = parser.parse_args()
    
    # Convert elements string to list
    element_list = args.elements.split(',')
    
    generate_permutations_file(
        output_file=args.output,
        elements=element_list,
        cumulative=args.cumulative,
        ascii_dimensions=args.ascii_dim,
        extra_entries=args.extra,
        group_count=args.groups
    )
