import base64
import os

class BinaryConverter:
    # @staticmethod é usado quando não precisa de self em nenhuma função
    @staticmethod
    def string_to_binary(input_string):
        return ''.join(format(ord(char), '08b') for char in input_string)

    @staticmethod
    def binary_to_string(binary_string):
        char_array = [chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8)]
        return ''.join(char_array)

    @staticmethod
    def invert_binary(binary_string):
        return ''.join('1' if bit == '0' else '0' for bit in binary_string)

    @staticmethod
    def reverse_binary(binary_string):
        return binary_string[::-1]

    @staticmethod
    def xor_with_fixed_vector(binary_string, fixed_vector):
        # Reutilizar o vetor fixo até cobrir o tamanho do binário
        fixed_vector = (fixed_vector * ((len(binary_string) // len(fixed_vector)) + 1))[:len(binary_string)]
        return ''.join(str(int(a) ^ int(b)) for a, b in zip(binary_string, fixed_vector))

    @staticmethod
    def binary_to_base64(binary_string):
        # Converte binário para array de bytes e depois para Base64
        byte_array = bytearray(int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8))
        return base64.b64encode(byte_array).decode()

    @staticmethod
    def base64_to_binary(base64_string):
        # Converte Base64 de volta para binário
        byte_array = base64.b64decode(base64_string)
        return ''.join(format(byte, '08b') for byte in byte_array)

class FileDecryptor:
    def __init__(self, fixed_vector):
        self.fixed_vector = fixed_vector

    def decrypt_file(self, file_path, fixed_vector2):
        with open(file_path, "r") as file:
            lines = file.readlines()
            original_extension = lines[0].strip()  # recuperando a extensão original
            encrypted_base64 = ''.join(lines[1:])  # resto é a Base64

        xored_binary = BinaryConverter.base64_to_binary(encrypted_base64)
        reversed_binary = BinaryConverter.xor_with_fixed_vector(xored_binary, fixed_vector2)
        inverted_binary = BinaryConverter.reverse_binary(reversed_binary)
        original_binary = BinaryConverter.invert_binary(inverted_binary)
        byte_array = bytearray(int(original_binary[i:i+8], 2) for i in range(0, len(original_binary), 8))

        new_file_path = file_path.replace(".zelda", original_extension)

        with open(new_file_path, "wb") as file:
            file.write(byte_array)

        os.remove(file_path)  # Remove o arquivo .zelda
        print(f"File decrypted and restored to: {new_file_path}")

    def process_directory(self, root_path, operation):
        script_name = os.path.basename(__file__)  # ignora o próprio script para não dar ruim
        for dirpath, _, filenames in os.walk(root_path):
            for file_name in filenames:
                if file_name == script_name:
                    continue  # ignora o próprio script
                file_path = os.path.join(dirpath, file_name)
                try:
                    if operation == 'encrypt' and not file_name.endswith(".zelda"):
                        self.encrypt_file(file_path)
                    elif operation == 'decrypt' and file_name.endswith(".zelda"):
                        self.decrypt_file(file_path, self.fixed_vector)  # Usa o fixed_vector já fornecido
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
                    continue  # passa para o próximo arquivo


if __name__ == "__main__":
    fixed_vector2 = input("Enter the fixed vector for decryption: ")  # Solicita o vetor fixo para descriptografar
    file_encryptor = FileDecryptor(fixed_vector2)  # Usa diretamente o fixed_vector2

    root_path = os.getcwd()

    file_encryptor.process_directory(root_path, 'decrypt')  # Processa a descriptografia
