import os, time
from typing import BinaryIO


class Magma:

    def __init__(self, path_to_s_blocks=None):
        self.__FOUR_BYTE_MASK = 0x_FFFF_FFFF
        self.__FOUR_BIT_MASK = 0xF
        self.__REQUIRED_KEY_LENGTH_BYTES = 32
        self.__BLOCK_SIZE_BYTES = 8
        self.__NUMBER_OF_ROUNDS = 32
        self.__NUMBER_OF_S_INDEXES = 8
        self.__KEY_BIT_SIZE = 256
        self.__BLOCK_MASK = 0x_FFFF_FFFF_FFFF_FFFF
        self.__KEY_MASK = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF
        if path_to_s_blocks:
            self.__S_BLOCKS = Magma.__get_s_blocks(path_to_s_blocks)
        else:
            self.__S_BLOCKS = [
                (12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1),
                (6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15),
                (11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0),
                (12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11),
                (7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12),
                (5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0),
                (8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7),
                (1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2)]

    def decrypt(self, byte_str: bytes = None, file_input=None,
                file_output=None, key: bytes = None):
        if byte_str:
            self.__check_byte_str(byte_str)
            byte_string = self.encrypt(byte_str, file_input, file_output, key, decrypt_mode=True)
            count_pad_bytes = byte_string[-8]
            return byte_string[:-8 - count_pad_bytes]
        elif file_input and file_output:
            self.encrypt(file_input=file_input, file_output=file_output, key=key, decrypt_mode=True)

    def encrypt(self, byte_str: bytes = None, file_input: BinaryIO = None,
                file_output: BinaryIO = None, key: bytes = None, decrypt_mode=False):
        if byte_str and file_input and file_output:
            raise Exception('Даны лишние аргументы.\nФункция поддерживает ИЛИ строку ИЛИ файл')

        if not key:
            raise ValueError("Был дан пустой ключ")
        else:
            key = int.from_bytes(key, 'big')
            key_bit_length = key.bit_length()
            if key_bit_length > self.__KEY_BIT_SIZE:
                raise ValueError(f'Дан слишком большой ключ. Ожидался ключ до {self.__KEY_BIT_SIZE} бит. '
                                f'Но был получен {key_bit_length} бит.')
            key &= self.__KEY_MASK
            sub_keys = self.__expand_key(key, decrypt_mode=decrypt_mode)

        if byte_str:
            self.__check_byte_str(byte_str)
            cipher_blocks = []
            byte_str = self.__pad(byte_str, decrypt_mode=decrypt_mode)
            count_of_steps = len(byte_str) // 8
            i_2 = 8
            for k in range(count_of_steps):
                block = byte_str[i_2 - 8:i_2]
                i_2 += 8
                block = int.from_bytes(block, 'big')
                cipher_blocks.append(self.__encrypt(block, sub_keys))
            return b''.join([block.to_bytes(self.__BLOCK_SIZE_BYTES, 'big') for block in cipher_blocks])

        elif file_input and file_output:
            if not decrypt_mode:
                self.__files_encrypt_actions(file_input, file_output, sub_keys)
            else:
                self.__file_decrypt_actions(file_input, file_output, sub_keys)
        else:
            raise ValueError('Получены некорректные аргументы.')

    def __file_decrypt_actions(self, file_input, file_output, sub_keys, decrypt_mode=True):
        input_size = os.fstat(file_input.fileno()).st_size
        number_of_blocks = input_size // 8
        file_input.seek(input_size - self.__BLOCK_SIZE_BYTES * 2)
        before_last_block: int = int.from_bytes(bytes=file_input.read(self.__BLOCK_SIZE_BYTES), byteorder='big')
        last_block: int = int.from_bytes(bytes=file_input.read(self.__BLOCK_SIZE_BYTES), byteorder='big')
        file_input.seek(0)
        for i in range(number_of_blocks - 2):
            block: bytes = file_input.read(self.__BLOCK_SIZE_BYTES)
            block: int = int.from_bytes(bytes=block, byteorder='big')
            cipher_block = self.__encrypt(block, sub_keys)
            file_output.write(cipher_block.to_bytes(length=8, byteorder='big'))
        last_block: bytes = self.__encrypt(last_block, sub_keys).to_bytes(length=self.__BLOCK_SIZE_BYTES,
                                                                          byteorder='big')
        pad_num = last_block[0]
        before_last_block: bytes = self.__encrypt(before_last_block, sub_keys).to_bytes(
            length=self.__BLOCK_SIZE_BYTES, byteorder='big')
        file_output.write(before_last_block[:-pad_num])

    def __files_encrypt_actions(self, file_input, file_output, sub_keys, decrypt_mode=False):
        input_size = os.fstat(file_input.fileno()).st_size
        if input_size == 0:
            raise Exception("Дан пустой файл для шифрования.")
        number_of_blocks = input_size // 8
        file_input.seek(number_of_blocks * 8)
        last_file_input_block = file_input.read(self.__BLOCK_SIZE_BYTES)
        last_file_input_block = self.__pad(byte_str=last_file_input_block, decrypt_mode=decrypt_mode)
        before_last = int.from_bytes(bytes=last_file_input_block[:self.__BLOCK_SIZE_BYTES], byteorder='big')
        last_file_input_block = int.from_bytes(bytes=last_file_input_block[self.__BLOCK_SIZE_BYTES:], byteorder='big')
        file_input.seek(0)
        for i in range(number_of_blocks):
            block: bytes = file_input.read(self.__BLOCK_SIZE_BYTES)
            block: int = int.from_bytes(bytes=block, byteorder='big')
            cipher_block = self.__encrypt(block, sub_keys)
            file_output.write(cipher_block.to_bytes(length=8, byteorder='big'))

        before_last = self.__encrypt(before_last, sub_keys)
        file_output.write(before_last.to_bytes(length=8, byteorder='big'))
        last_file_input_block = self.__encrypt(last_file_input_block, sub_keys)
        file_output.write(last_file_input_block.to_bytes(length=8, byteorder='big'))

    def __expand_key(self, key: int, decrypt_mode=False):
        sub_keys = []
        byte_step = 4
        for i in range(byte_step, self.__REQUIRED_KEY_LENGTH_BYTES + 1, byte_step):
            sub_keys.append(key & self.__FOUR_BYTE_MASK)
            key >>= 0x20
        sub_keys.reverse()
        sub_keys = sub_keys * 3 + sub_keys[::-1]
        if decrypt_mode:
            sub_keys.reverse()
        return sub_keys

    @staticmethod
    def __check_byte_str(obj_to_check):
        if not isinstance(obj_to_check, bytes):
            raise ValueError(f"Ожидался тип переменной bytes, но {type(obj_to_check)} был получен.")

    def __pad(self, byte_str, decrypt_mode=False) -> bytes:
        if not decrypt_mode:
            length = len(byte_str)
            number_of_add_bytes: int = self.__BLOCK_SIZE_BYTES - length % self.__BLOCK_SIZE_BYTES
            if number_of_add_bytes != self.__BLOCK_SIZE_BYTES:
                byte_str += (b'\0' * number_of_add_bytes) + (number_of_add_bytes.to_bytes(1, 'big') + b'\0' * 7)
            else:
                number_of_add_bytes = 0
                byte_str += (number_of_add_bytes.to_bytes(1, 'big') + b'\0' * 7)
        return byte_str

    @staticmethod
    def __get_s_blocks(path):
        with open(path, 'r') as file:
            s_blocks = file.read()
        return tuple(tuple(map(int, item.split())) for item in s_blocks.split('\n'))

    def __feistel_func(self, four_byte_num: int, sub_key) -> int:
        result_four_byte_num = 0
        mod_2in32_sum = (four_byte_num + sub_key) & self.__FOUR_BYTE_MASK
        i = 0
        while i != 8:
            index = mod_2in32_sum & self.__FOUR_BIT_MASK
            s_item = self.__S_BLOCKS[i][index] & self.__FOUR_BIT_MASK
            result_four_byte_num |= (s_item << (4 * i))
            i += 1
            mod_2in32_sum >>= 4
        result_four_byte_num = ((result_four_byte_num << 11) | (result_four_byte_num >> 21)) & self.__FOUR_BYTE_MASK
        return result_four_byte_num

    def __encrypt(self, eight_bytes_block: int, sub_keys) -> int:
        left = (eight_bytes_block >> 0x20) & self.__FOUR_BYTE_MASK
        right = eight_bytes_block & self.__FOUR_BYTE_MASK
        for i in range(self.__NUMBER_OF_ROUNDS - 1):  # Обработка 31 из 32 раундов
            feistel_modified = self.__feistel_func(right, sub_keys[i])
            xor_sum = left ^ feistel_modified
            left, right = right, xor_sum

        # Обработка последнего шага
        feistel_modified = self.__feistel_func(right, sub_keys[-1])
        xor_sum = left ^ feistel_modified
        cipher_block = (xor_sum << 0x20) | right
        return cipher_block


class Application:
    def __init__(self):
        self.__RED = '\033[31m'
        self.__DEFAULT = '\033[39m'
        self.__GREEN = '\033[32m'
        self.__ENCRYPT_MESSAGE = 0
        self.__ENCRYPT_FILE = 1
        self.__DECRYPT_MESSAGE = 2
        self.__DECRYPT_FILE = 3
        self.__EXIT = 4
        self.__magma = Magma()

    def start(self):
        working = True
        while working:
            operating_mode = self.__get_operating_mode()
            if operating_mode == self.__EXIT:
                working = False
            else:
                try:
                    key: bytes = self.__get_not_empty_str(to_input_func_phrase='Введите значение ключа: ').encode()
                    if operating_mode == self.__ENCRYPT_MESSAGE:
                        self.__encrypt_console_interface(key=key)
                    elif operating_mode == self.__DECRYPT_MESSAGE:
                        self.__decrypt_console_interface(key=key)
                    elif operating_mode == self.__ENCRYPT_FILE:
                        self.__encrypt_file_interface(key=key)
                    elif operating_mode == self.__DECRYPT_FILE:
                        self.__decrypt_file_interface(key=key)
                except ValueError:
                    self.__show_error_message('Введен слишком большой ключ.')



    def __decrypt_file_interface(self, key):
        file_descriptors = []
        number_of_files = 2
        for i in range(number_of_files):
            bad_file = True
            while bad_file:
                if i == 0:
                    filename = self.__get_not_empty_str('Введите имя файла для расшифрования: ')
                else:
                    filename = self.__get_not_empty_str('Введите имя файла для сохранения результата: ')
                try:
                    if i == 0:
                        file = open(filename, 'rb')
                    else:
                        if file_descriptors[0].name == filename:
                            self.__show_error_message('Это очень плохая идея.')
                            continue
                        else:
                            file = open(filename, 'wb')
                    file_descriptors.append(file)
                    bad_file = False
                except (FileExistsError, FileNotFoundError, NotADirectoryError):
                    self.__show_error_message(f'Файл не найден\nТекущая рабочая директория: {os.getcwd()}')
        start = time.time()
        self.__magma.decrypt(file_input=file_descriptors[0], file_output=file_descriptors[1], key=key)
        file_descriptors[0].close()
        file_descriptors[1].close()
        print(f'{self.__RED}Выполнено за {time.time() - start} с.{self.__DEFAULT}\n')

    def __encrypt_file_interface(self, key):
        file_descriptors = []
        number_of_files = 2
        for i in range(number_of_files):
            bad_file = True
            while bad_file:
                if i == 0:
                    filename = self.__get_not_empty_str('Введите имя шифруемого файла: ')
                else:
                    filename = self.__get_not_empty_str('Введите имя файла для сохранения результата: ')
                try:
                    if i == 0:
                        file = open(filename, 'rb')
                    else:
                        if file_descriptors[0].name == filename:
                            self.__show_error_message('Это очень плохая идея.')
                            continue
                        else:
                            file = open(filename, 'wb')
                    file_descriptors.append(file)
                    bad_file = False
                except (FileExistsError, FileNotFoundError, NotADirectoryError):
                    self.__show_error_message(f'Файл не найден\nТекущая рабочая директория: {os.getcwd()}')
        start = time.time()
        self.__magma.encrypt(file_input=file_descriptors[0], file_output=file_descriptors[1], key=key)
        file_descriptors[0].close()
        file_descriptors[1].close()
        print(f'{self.__RED}Выполнено за {time.time() - start} с.{self.__DEFAULT}\n')

    def __decrypt_console_interface(self, key):
        bad_cipher_text = True
        cipher_text = b''
        while bad_cipher_text:
            cipher_text = self.__get_not_empty_str(to_input_func_phrase='Введите hex-строку шифртекста: ')
            cipher_text = self.__cipher_text_to_bytes(cipher_text)
            if cipher_text:
                bad_cipher_text = False
        start = time.time()
        decrypted = self.__magma.decrypt(byte_str=cipher_text, key=key).decode()
        with open('./data/decrypted.txt', 'w', encoding='utf-8') as file:
            file.write(decrypted)
        print(f'{self.__GREEN}Расшифрованное сообщение{self.__DEFAULT}: {decrypted}')
        print(f'{self.__RED}Выполнено за {time.time() - start} с.{self.__DEFAULT}\n')

    def __cipher_text_to_bytes(self, cipher_text: str) -> bytes:
        try:
            return bytes.fromhex(cipher_text)
        except ValueError:
            self.__show_error_message('Введенная строка не относится к hex-строкам.')
            return b''

    def __encrypt_console_interface(self, key):
        message: bytes = self.__get_not_empty_str(to_input_func_phrase='Введите строку для шифрования: ').encode()
        start = time.time()
        cipher_text = self.__magma.encrypt(byte_str=message, key=key)
        with open('./data/ciphertext.txt', 'wb') as file:
            file.write(cipher_text)
        print(f'Шифртекст: {self.__GREEN}{cipher_text.hex()}{self.__DEFAULT}')
        print(f'{self.__RED}Выполнено за {time.time() - start} с.{self.__DEFAULT}\n')

    def __show_error_message(self, message: str):
        print(f'{self.__RED}{message}{self.__DEFAULT}\n')

    def __get_not_empty_str(self, to_input_func_phrase: str) -> str:
        empty_input = True
        user_input = ''
        while empty_input:
            user_input = input(f'{self.__GREEN}{to_input_func_phrase}{self.__DEFAULT}')
            if not user_input:
                self.__show_error_message('Введенная строка не должна быть пустой.')
            else:
                empty_input = False
        return user_input

    def __get_operating_mode(self):
        bad_mode = True
        mode = -1
        while bad_mode:
            mode = self.__get_not_empty_str(f'Выберите режим работы:{self.__DEFAULT}\n'
                                            f'[{self.__GREEN}0{self.__DEFAULT}] -> Зашифровать сообщение\n'
                                            f'[{self.__GREEN}1{self.__DEFAULT}] -> Зашифровать файл\n'
                                            f'[{self.__GREEN}2{self.__DEFAULT}] -> Расшифровать сообщение\n'
                                            f'[{self.__GREEN}3{self.__DEFAULT}] -> Расшифровать файл\n'
                                            f'[{self.__GREEN}4{self.__DEFAULT}] -> Прекратить работу\n'
                                            '>>> ')
            try:
                mode = int(mode)
                if mode not in range(5):
                    raise ValueError
                bad_mode = False
            except ValueError:
                self.__show_error_message('Введено недопустимое значение.')
        return mode



if __name__ == '__main__':
    a = Application()
    a.start()
