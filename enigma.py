import json

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
        self.initial_wheels = wheels[:]
        self.wheels = wheels[:]
        self.reflector_map = reflector_map

    def encrypt(self, message):
        pass

class JSONFileException(Exception):
    """Exception raised"""
    pass

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

    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise JSONFileException(f"Error loading JSON file: {e}")
