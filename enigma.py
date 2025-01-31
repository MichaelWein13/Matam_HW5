import json
import sys

class Enigma:
    """
    Implements the Enigma encryption machine.
    
    Methods:
    - __init__: Constructor that takes three arguments:
        1. hash_map: A dictionary where keys are characters and values are numbers between 0 and 25 (inclusive).
        2. wheels: A list of three elements representing the initial state of the wheels.
        3. reflector_map: A dictionary where both keys and values are characters.
        
    - encrypt: Encrypts a given message string using the specified algorithm.
      After encryption, the Enigma machine resets to its initial state.
    """
    
    def __init__(self, hash_map, wheels, reflector_map):
        self.hash_map = hash_map
        self.init_wheels = wheels[:]
        self.wheels = wheels[:]
        self.reflector_map = reflector_map

    def encrypt(self, message):
        encrypted_message = []
        encrypted_count = 0

        for c in message:
            if c not in self.hash_map:
                encrypted_message.append(c)
            else:
                value = (((2 * self.wheels[0]) - self.wheels[1] + self.wheels[2]) % 26)
                i = self.hash_map[c]
                if value != 0:
                    i += value
                else:
                    i += 1

                i %= 26
                c1 = self.get_key_from_value(self.hash_map, i)
                c2 = self.reflector_map[c1]

                i = self.hash_map[c2]

                if value != 0:
                    i -= value
                else:
                    i -= 1

                i %= 26
                c3 = self.get_key_from_value(self.hash_map, i)
                encrypted_message.append(c3)
                encrypted_count += 1

            self._advance_wheels(encrypted_count)

        self.wheels = self.init_wheels[:]
        return ''.join(encrypted_message)

    def _advance_wheels(self, encrypted_count):
        self.wheels[0] += 1
        if self.wheels[0] > 8:
            self.wheels[0] = 1

        # for even indices
        if encrypted_count % 2 == 0:
            self.wheels[1] *= 2
        else:
            self.wheels[1] -= 1

        if encrypted_count != 0 and encrypted_count % 10 == 0:
            self.wheels[2] = 10
        elif encrypted_count != 0 and encrypted_count % 3 == 0:
            self.wheels[2] = 5
        else:
            self.wheels[2] = 0
    @staticmethod
    def get_key_from_value(mapping, target_value):
        """Returns the key corresponding to the given value in the dictionary."""
        for key, value in mapping.items():
            if value == target_value:
                return key
        return None  # Handle the case where the value is not found


class JSONFileException(Exception):
    """Exception raised"""
    pass

def print_usage_and_exit():
    """Prints the message to stderr and exits."""
    sys.stderr.write("Usage: python3 enigma.py -c <config_file> -i <input_file> -o <output_file>\n")
    sys.exit(1)
def print_error_and_exit():
    """Prints an error message to stderr and exits."""
    sys.stderr.write("The enigma script has encountered an error\n")
    sys.exit(1)
def parse_arguments():
    """
    Parses command-line arguments and returns them as a dictionary.
    Exits with usage message if arguments are incorrect.
    """
    args = sys.argv[1:]  # Exclude the script name from the arguments

    if len(args) != 6:
        print_usage_and_exit()  # If the number of arguments is not exactly 6, show usage and exit

    # Expected flags
    flags = {"-c": None, "-i": None, "-o": None}  # A dictionary to store the flags and their corresponding values

    try:
        for i in range(0, len(args), 2):  # Iterate over arguments, stepping by 2 (flag, value pairs)
            flag, value = args[i], args[i + 1]  # Get the flag and its associated value
            if flag in flags and flags[flag] is None:  # If the flag is valid and not yet assigned
                flags[flag] = value  # Assign the value to the flag in the dictionary
            else:
                print_usage_and_exit()  # If the flag is invalid or already assigned, exit with usage message
    except IndexError:
        print_usage_and_exit()  # If there's an index error (missing value after a flag), show usage and exit

    if flags["-c"] is None or flags["-i"] is None:
        print_usage_and_exit()

    return flags["-c"], flags["-i"], flags["-o"]

def load_enigma_from_path(path):
    """
    Loads Enigma configuration from a JSON file and returns an Enigma object.

    :param path: Path to the JSON file.
    :return: Enigma object initialized with the JSON data.
    :raises JSONFileException: If there is an error reading or parsing the file.
    """
    try:
        with open(path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        if not all(key in data for key in ["hash_map", "wheels", "reflector_map"]):
            raise JSONFileException("Invalid JSON structure: missing required keys.")
        return Enigma(data["hash_map"], data["wheels"], data["reflector_map"])

    except (FileNotFoundError, json.JSONDecodeError, PermissionError) as e:
        raise JSONFileException(f"Error loading JSON file: {e}")
def main():
    try:
        config_path, input_path, output_path = parse_arguments()
        enigma = load_enigma_from_path(config_path)

        # get input file
        with open(input_path, 'r', encoding='utf-8') as input_file:
            plaintext = input_file.read()

        # Encrypt message
        ciphertext = enigma.encrypt(plaintext)

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as output_file:
                output_file.write(ciphertext)
        else:
            print(ciphertext)

    except (JSONFileException, FileNotFoundError, PermissionError):
        print_error_and_exit()
if __name__ == "__main__":
    main()
