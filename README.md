# File Encryptor and Decryptor with Header

This Java program provides a secure way to encrypt and decrypt files using a specified password. It includes a unique approach by adding a header with a salt value to the encrypted file to ensure that files are not accidentally re-encrypted and to aid in the decryption process. Additionally, it incorporates a mechanism to protect against brute force decryption attempts by corrupting the file after 10 consecutive failed decryption attempts.

## Features

- **Header with Salt Value**: Adds a unique header (`salt16::`) followed by a 16-byte salt to the encrypted file.
- **Encryption and Decryption**: Supports encryption and decryption of files using AES encryption algorithm with a password-specified key.
- **Brute Force Protection**: Corrupts the file after 10 consecutive failed decryption attempts to prevent brute force attacks.
- **File Encryption Check**: Prevents re-encryption of already encrypted files.

## How to Use

1. **Compile the Java Program**:
    - Ensure you have Java installed on your system.
    - Compile the `FileEncryptorDecryptorWithHeader.java` file using your Java compiler (e.g., `javac FileEncryptorDecryptorWithHeader.java`).

2. **Running the Program**:
    - Use the command line to run the program with the required arguments.
    - The program takes four arguments: mode (0 for decrypt, 1 for encrypt), input file path, output file path, and password.

### Encryption Example

```shell
java FileEncryptorDecryptorWithHeader 1 input.txt encrypted.txt mypassword
