import random
import string
import copy
import logging
import json

logger = logging.getLogger("MutationEngine")

class MutationEngine:
    """
    A mutation engine implementing AFL-style mutation strategies with context aware inputs (HTTP)
    
    This class focuses on the fundamental mutation operations:
    - bitflip: Flips random bits in inputs
    - byteflip: Flips random bytes
    - insert_bytes: Inserts bytes from another source
    - random_byte: Changes random bytes (string or numeric versions)
    - delete_bytes: Removes bytes
    - random_mutation: Selects one mutation strategy randomly
    """
    
    def __init__(self):
        # Special characters that often trigger parsing errors
        self.special_chars = [
            "'", "\"", "<", ">", "&", ";", "|", "`", "$", "(", ")", "*", "\\", "\0", 
            "\n", "\r", "%n", "%s"
        ]
        
        # Interesting values that often trigger edge cases
        self.interesting_numbers = [
            0, -1, 1, 255, 256, 0x7F, 0xFF, 0x7FFF, 0xFFFF, 0x80000000, 0xFFFFFFFF
        ]
    
    # --- Core Mutation Strategies ---
    def _mutate_integer(self, value):
        """Apply different integer mutation strategies including metamorphic"""
        strategy = random.choice([
            "interesting", "arithmetic", "bitflip", "metamorphic"
        ])
        
        if strategy == "interesting":
            return random.choice(self.interesting_numbers)
            
        elif strategy == "arithmetic":
            operators = [
                lambda x: x + 1,
                lambda x: x - 1,
                lambda x: x * 2,
                lambda x: x // 2,
                lambda x: -x,
                lambda x: x ^ 0xFFFFFFFF,
                lambda x: x + random.randint(-10, 10)
            ]
            return random.choice(operators)(value)
            
        elif strategy == "bitflip":
            byte_length = max(1, (value.bit_length() + 7) // 8)
            try:
                bytes_value = value.to_bytes(byte_length, byteorder='little', signed=True)
                result = bytearray(bytes_value)
                pos = random.randint(0, len(result) - 1)
                bit = 1 << random.randint(0, 7)
                result[pos] ^= bit
                return int.from_bytes(result, byteorder='little', signed=True)
            except (OverflowError, AttributeError):
                return value + random.randint(-100, 100)
        
        elif strategy == "metamorphic":
            return random.choice([
                value + 1000,
                -value,
                0x7FFFFFFF,
                value ^ 0xFFFFFFFF,
                value * 100
            ])

    def _change_random_char(self, string_data):
        """Enhanced string mutation with metamorphic strategies"""
        strategies = [
            "replace_char",
            "append_special",
            "truncate",
            "uppercase",
            "replace_a",
            "random_case"
        ]
        
        strategy = random.choice(strategies)
        
        if strategy == "replace_char":
            if not string_data:
                return string_data
            char_list = list(string_data)
            pos = random.randint(0, len(char_list) - 1)
            char_list[pos] = random.choice(string.printable)
            return ''.join(char_list)
            
        elif strategy == "append_special":
            return string_data + random.choice(self.special_chars)
            
        elif strategy == "truncate":
            return string_data[:-1] if len(string_data) > 0 else string_data
            
        elif strategy == "uppercase":
            return string_data.upper()
            
        elif strategy == "replace_a":
            return string_data.replace('a', 'aaaaa').replace('A', 'AAAAA')
            
        elif strategy == "random_case":
            return ''.join(random.choice([c.upper(), c.lower()]) for c in string_data)
            
        return string_data

    # --- Core AFL-style Mutation Strategies ---
    
    def bitflip(self, data, num_flips=1):
        """Flips random bits in the input (byte-level implementation)"""
        if isinstance(data, dict):
            # Convert to JSON string for bit manipulation
            data_str = json.dumps(data)
            mutated_str = self._bitflip_bytes(data_str.encode(), num_flips)
            try:
                # Try to convert back to dictionary
                return json.loads(mutated_str.decode('utf-8', errors='ignore'))
            except:
                # Fall back to the original data if JSON is corrupted
                return data
        elif isinstance(data, str):
            data_bytes = data.encode()
            mutated_bytes = self._bitflip_bytes(data_bytes, num_flips)
            return mutated_bytes.decode('utf-8', errors='ignore')
        else:
            # Return data unchanged if not a supported type
            return data

    def _bitflip_bytes(self, data_bytes, num_flips=1):
        """Internal method to flip bits in byte data"""
        if not data_bytes:
            return data_bytes
            
        result = bytearray(data_bytes)
        for _ in range(num_flips):
            # Select a random byte position
            pos = random.randint(0, len(result) - 1)
            # Select a random bit position within the byte
            bit = 1 << random.randint(0, 7)
            # Flip the bit
            result[pos] ^= bit
            
        return result
    
    def byteflip(self, data, num_flips=1):
        """Flips random bytes in the input"""
        if isinstance(data, dict):
            # Convert to JSON string for byte manipulation
            data_str = json.dumps(data)
            mutated_str = self._byteflip_bytes(data_str.encode(), num_flips)
            try:
                # Try to convert back to dictionary
                return json.loads(mutated_str.decode('utf-8', errors='ignore'))
            except:
                # Fall back to the original data if JSON is corrupted
                return data
        elif isinstance(data, str):
            data_bytes = data.encode()
            mutated_bytes = self._byteflip_bytes(data_bytes, num_flips)
            return mutated_bytes.decode('utf-8', errors='ignore')
        else:
            # Return data unchanged if not a supported type
            return data
    
    def _byteflip_bytes(self, data_bytes, num_flips=1):
        """Internal method to flip bytes"""
        if not data_bytes:
            return data_bytes
        
        result = bytearray(data_bytes)
        for _ in range(num_flips):
            if not result:
                break
            # Select a random byte position
            pos = random.randint(0, len(result) - 1)
            # Flip all bits in the byte (XOR with 0xFF)
            result[pos] ^= 0xFF
            
        return result
    
    def insert_bytes(self, data, num_inserts=1):
        """Inserts random bytes into the input"""
        if isinstance(data, dict):
            # For dictionaries, we'll insert into a random string field
            mutated = copy.deepcopy(data)
            for _ in range(num_inserts):
                # Find string fields to modify
                string_fields = [(k, v) for k, v in mutated.items() if isinstance(v, str)]
                if string_fields:
                    key, value = random.choice(string_fields)
                    mutated[key] = self._insert_bytes_in_str(value)
            return mutated
        elif isinstance(data, str):
            result = data
            for _ in range(num_inserts):
                result = self._insert_bytes_in_str(result)
            return result
        else:
            # Return data unchanged if not a supported type
            return data
    
    def _insert_bytes_in_str(self, string_data):
        """Insert a random character into a string"""
        if not string_data:
            return random.choice(string.printable)
        
        pos = random.randint(0, len(string_data))
        char = random.choice(string.printable)
        return string_data[:pos] + char + string_data[pos:]
    
    def random_byte_str(self, data, num_changes=1):
        """Changes random bytes in string data using enhanced mutations"""
        if isinstance(data, dict):
            mutated = copy.deepcopy(data)
            for _ in range(num_changes):
                string_fields = [(k, v) for k, v in mutated.items() if isinstance(v, str)]
                if string_fields:
                    key, value = random.choice(string_fields)
                    mutated[key] = self._change_random_char(value)
            return mutated
        elif isinstance(data, str):
            result = data
            for _ in range(num_changes):
                result = self._change_random_char(result)
            return result
        else:
            return data

    def random_byte_int(self, data, num_changes=1):
        """Changes random bytes in integer data with metamorphic support"""
        if isinstance(data, dict):
            mutated = copy.deepcopy(data)
            for _ in range(num_changes):
                int_fields = [(k, v) for k, v in mutated.items() if isinstance(v, int)]
                if int_fields:
                    key, value = random.choice(int_fields)
                    mutated[key] = self._mutate_integer(value)
            return mutated
        elif isinstance(data, int):
            return self._mutate_integer(data)
        else:
            return data
    
    def _change_random_char(self, string_data):
        """Change a random character in a string"""
        if not string_data:
            return string_data
        
        char_list = list(string_data)
        if not char_list:
            return string_data
            
        pos = random.randint(0, len(char_list) - 1)
        char_list[pos] = random.choice(string.printable)
        return ''.join(char_list)
    
    def _mutate_integer(self, value):
        """Apply different integer mutation strategies"""
        strategy = random.choice(["interesting", "arithmetic", "bitflip"])
        
        if strategy == "interesting":
            # Replace with an "interesting" value
            return random.choice(self.interesting_numbers)
            
        elif strategy == "arithmetic":
            # Apply AFL-style arithmetic mutations
            operators = [
                lambda x: x + 1,
                lambda x: x - 1,
                lambda x: x * 2,
                lambda x: x // 2,
                lambda x: -x,
                lambda x: x ^ 0xFFFFFFFF,  # bitwise NOT (32-bit)
                lambda x: x + random.randint(-10, 10)
            ]
            return random.choice(operators)(value)
            
        elif strategy == "bitflip":
            # Bit-level mutations on the integer
            # Convert to bytes first
            byte_length = max(1, (value.bit_length() + 7) // 8)
            try:
                # Handle both positive and negative integers
                bytes_value = value.to_bytes(byte_length, byteorder='little', signed=True)
                result = bytearray(bytes_value)
                # Flip a random bit
                pos = random.randint(0, len(result) - 1)
                bit = 1 << random.randint(0, 7)
                result[pos] ^= bit
                # Convert back to integer
                return int.from_bytes(result, byteorder='little', signed=True)
            except (OverflowError, AttributeError):
                # Fallback for very large integers or other issues
                return value + random.randint(-100, 100)
    
    def delete_bytes(self, data, num_deletes=1):
        """Deletes random bytes from the input"""
        if isinstance(data, dict):
            # For dictionaries, we'll delete characters from string fields
            mutated = copy.deepcopy(data)
            for _ in range(num_deletes):
                # Find string fields to modify
                string_fields = [(k, v) for k, v in mutated.items() if isinstance(v, str) and len(v) > 1]
                if string_fields:
                    key, value = random.choice(string_fields)
                    mutated[key] = self._delete_char(value)
            return mutated
        elif isinstance(data, str) and len(data) > 0:
            result = data
            for _ in range(min(num_deletes, len(data))):
                if not result:
                    break
                result = self._delete_char(result)
            return result
        else:
            # Return data unchanged if not a supported type or empty string
            return data
    
    def _delete_char(self, string_data):
        """Delete a random character from a string"""
        if not string_data:
            return string_data
            
        pos = random.randint(0, len(string_data) - 1)
        return string_data[:pos] + string_data[pos+1:]
    
    def random_mutation(self, data):
        """Apply a randomly selected mutation strategy"""
        strategy = random.choice([
            "bitflip",
            "byteflip",
            "insert_bytes",
            "random_byte_str", 
            "random_byte_int",
            "delete_bytes",
            "special_chars"
        ])
        
        if strategy == "bitflip":
            return self.bitflip(data, random.randint(1, 3))
        elif strategy == "byteflip":
            return self.byteflip(data, random.randint(1, 2))
        elif strategy == "insert_bytes":
            return self.insert_bytes(data, random.randint(1, 3))
        elif strategy == "random_byte_str":
            return self.random_byte_str(data, random.randint(1, 3))
        elif strategy == "random_byte_int":
            return self.random_byte_int(data, random.randint(1, 2))
        elif strategy == "delete_bytes":
            return self.delete_bytes(data, random.randint(1, 3))
        elif strategy == "special_chars" and (isinstance(data, str) or isinstance(data, dict)):
            # Insert special characters that often trigger vulnerabilities
            if isinstance(data, str):
                pos = random.randint(0, len(data))
                char = random.choice(self.special_chars)
                return data[:pos] + char + data[pos:]
            elif isinstance(data, dict):
                mutated = copy.deepcopy(data)
                string_fields = [(k, v) for k, v in mutated.items() if isinstance(v, str)]
                if string_fields:
                    key, value = random.choice(string_fields)
                    pos = random.randint(0, len(value))
                    char = random.choice(self.special_chars)
                    mutated[key] = value[:pos] + char + value[pos:]
                return mutated
        
        # Default: return unchanged
        return data
    
    # --- High-level mutation methods for API fuzzing ---
    
    def mutate_payload(self, payload, num_mutations=1):
        """Apply multiple mutations to a JSON payload (API-aware)"""
        if not payload:
            return payload
            
        result = copy.deepcopy(payload)
        
        for _ in range(num_mutations):
            # For dictionaries, we can either mutate a field or the entire object
            if isinstance(result, dict) and result:
                approach = random.choice(["field_mutation", "object_mutation"])
                
                if approach == "field_mutation":
                    # Mutate a specific field based on its type
                    if not result:  # Safety check for empty dict
                        continue
                        
                    key = random.choice(list(result.keys()))
                    value = result[key]
                    
                    if isinstance(value, str):
                        mutation = random.choice([
                            "random_byte_str", 
                            "insert_bytes", 
                            "delete_bytes",
                            "special_chars"
                        ])
                    elif isinstance(value, int):
                        mutation = "random_byte_int"
                    elif isinstance(value, dict) or isinstance(value, list):
                        # Recursive mutation
                        result[key] = self.mutate_payload(value, 1)
                        continue
                    else:
                        # Skip unsupported types
                        continue
                        
                    # Apply the selected mutation to the field
                    if mutation == "random_byte_str":
                        result[key] = self.random_byte_str(value)
                    elif mutation == "insert_bytes":
                        result[key] = self.insert_bytes(value)
                    elif mutation == "delete_bytes":
                        result[key] = self.delete_bytes(value)
                    elif mutation == "special_chars" and isinstance(value, str):
                        pos = random.randint(0, len(value))
                        char = random.choice(self.special_chars)
                        result[key] = value[:pos] + char + value[pos:]
                    elif mutation == "random_byte_int":
                        result[key] = self.random_byte_int(value)
                        
                else:  # object_mutation
                    # AFL-style mutations on the entire object
                    mutation = random.choice([
                        "add_field",
                        "remove_field",
                        "bitflip",
                        "byteflip"
                    ])
                    
                    if mutation == "add_field":
                        # Add a random field with random content
                        field_name = ''.join(random.choices(string.ascii_letters, k=random.randint(3, 8)))
                        field_value = random.choice([
                            "test_value",
                            random.randint(-1000, 1000),
                            True,
                            None
                        ])
                        result[field_name] = field_value
                        
                    elif mutation == "remove_field" and result:
                        # Remove a random field
                        key = random.choice(list(result.keys()))
                        del result[key]
                        
                    elif mutation == "bitflip":
                        # Apply bitflip to the whole object
                        result = self.bitflip(result)
                        
                    elif mutation == "byteflip":
                        # Apply byteflip to the whole object
                        result = self.byteflip(result)
            
            elif isinstance(result, list) and result:
                # For lists, either mutate an element or the structure
                approach = random.choice(["element_mutation", "list_mutation"])
                
                if approach == "element_mutation" and result:
                    # Choose a random element to mutate
                    idx = random.randint(0, len(result) - 1)
                    value = result[idx]
                    
                    # Use recursive mutation for complex types
                    if isinstance(value, (dict, list)):
                        result[idx] = self.mutate_payload(value, 1)
                    else:
                        # Apply random mutation 
                        result[idx] = self.random_mutation(value)
                        
                else:  # list_mutation
                    # Modify the list structure
                    operation = random.choice(["add", "remove", "duplicate"])
                    
                    if operation == "add":
                        # Add a random element
                        if result:
                            # Clone and potentially mutate an existing element
                            source = random.choice(result)
                            if isinstance(source, (dict, list)):
                                new_item = self.mutate_payload(copy.deepcopy(source), 1)
                            else:
                                new_item = self.random_mutation(source)
                            result.append(new_item)
                        else:
                            # Add a simple value for empty lists
                            result.append(random.choice([
                                "test_value",
                                random.randint(-1000, 1000),
                                True,
                                {}
                            ]))
                            
                    elif operation == "remove" and result:
                        # Remove a random element
                        idx = random.randint(0, len(result) - 1)
                        result.pop(idx)
                        
                    elif operation == "duplicate" and result:
                        # Duplicate a random element
                        idx = random.randint(0, len(result) - 1)
                        result.append(result[idx])
            
            else:
                # For primitive types, use basic mutations
                result = self.random_mutation(result)
                
        return result