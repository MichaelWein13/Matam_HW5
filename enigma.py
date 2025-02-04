import json
import sys

# Global Constants
ALPHABET_SIZE = 26
MAX_WHEEL_0 = 8
EVEN_INDEX_MULTIPLIER = 2
ODD_INDEX_DECREMENT = 1
WHEEL_2_RESET_10 = 10
WHEEL_2_RESET_5 = 5
WHEEL_2_RESET_0 = 0
NUM_ARGS_1 = 4
NUM_ARGS_2 = 6


class Enigma:
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
                value = (((2 * self.wheels[0]) - self.wheels[1] + self.wheels[2]) % ALPHABET_SIZE)
                i = self.hash_map[c]
                i += value if value != 0 else 1
                i %= ALPHABET_SIZE
                c1 = self.get_key_from_value(self.hash_map, i)
                c2 = self.reflector_map[c1]
                i = self.hash_map[c2]
                i -= value if value != 0 else 1
                i %= ALPHABET_SIZE
                c3 = self.get_key_from_value(self.hash_map, i)
                encrypted_message.append(c3)
                encrypted_count += 1
            self._advance_wheels(encrypted_count)
        self.wheels = self.init_wheels[:]
        return ''.join(encrypted_message)

    def _advance_wheels(self, encrypted_count):
        self.wheels[0] += 1
        if self.wheels[0] > MAX_WHEEL_0:
            self.wheels[0] = 1

        if encrypted_count % 2 == 0:
            self.wheels[1] *= EVEN_INDEX_MULTIPLIER
        else:
            self.wheels[1] -= ODD_INDEX_DECREMENT

        if encrypted_count % 10 == 0:
            self.wheels[2] = WHEEL_2_RESET_10
        elif encrypted_count % 3 == 0:
            self.wheels[2] = WHEEL_2_RESET_5
        else:
            self.wheels[2] = WHEEL_2_RESET_0

    @staticmethod
    def get_key_from_value(mapping, target_value):
        for key, value in mapping.items():
            if value == target_value:
                return key
        return None

class JSONFileException(Exception):
    pass

def print_usage_and_exit():
    sys.stderr.write("Usage: python3 enigma.py -c <config_file> -i <input_file> -o <output_file>\n")
    sys.exit(1)

def print_error_and_exit():
    sys.stderr.write("The enigma script has encountered an error\n")
    sys.exit(1)

def parse_arguments():
    args = sys.argv[1:]
    if len(args) not in [NUM_ARGS_1, NUM_ARGS_2]:
        print_usage_and_exit()

    flags = {"-c": None, "-i": None, "-o": None}
    try:
        for i in range(0, len(args), 2):
            flag, value = args[i], args[i + 1]
            if flag in flags and flags[flag] is None:
                flags[flag] = value
            else:
                print_usage_and_exit()
    except IndexError:
        print_usage_and_exit()

    if flags["-c"] is None or flags["-i"] is None:
        print_usage_and_exit()

    return flags["-c"], flags["-i"], flags["-o"]

def load_enigma_from_path(path):
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
        with open(input_path, 'r', encoding='utf-8') as input_file:
            ciphertext = "".join(enigma.encrypt(line) for line in input_file)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as output_file:
                output_file.write(ciphertext)
        else:
            print(ciphertext)
    except (JSONFileException, FileNotFoundError, PermissionError):
        print_error_and_exit()

if __name__ == "__main__":
    main()
