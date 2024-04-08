import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

public class FileEncryptorDecryptorWithHeader {

    private static final String ENCRYPTION_HEADER = "salt16::";
    private static final int SALT_SIZE = 16;
    private static int failedAttempts = 0;

    private static SecretKey getKeyFromPassword(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private static void corruptFile(String filePath) throws Exception {
        try (FileOutputStream out = new FileOutputStream(filePath)) {
            out.write(new byte[SALT_SIZE]); // Overwrite the file with random bytes
            System.out.println("Failed attempts limit reached. File has been corrupted.");
        }
    }

    private static void processFile(Cipher cipher, FileInputStream fis, FileOutputStream fos) throws Exception {
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) fos.write(output);
        }
        byte[] output = cipher.doFinal();
        if (output != null) fos.write(output);
    }

    public static void encrypt(String password, String inputFile, String outputFile) throws Exception {

        // create 16 bytes salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);

        // create key
        SecretKey key = getKeyFromPassword(password, salt);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);


        FileInputStream fis = null;
        FileOutputStream fos = null;

        try {
            fis = new FileInputStream(inputFile);
            fos = new FileOutputStream(outputFile);
            // write the salt identifier into file header
            fos.write(ENCRYPTION_HEADER.getBytes());
            fos.write(salt);

            processFile(cipher, fis, fos);
            System.out.println("Encryption complete.");
        } finally {
            if (fis != null){
                fis.close();
            }
            if (fos != null){
                fos.close();
            }
        }
    }

    public static void decrypt(String password, String inputFile, String outputFile) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            byte[] headerBytes = new byte[ENCRYPTION_HEADER.length()];
            if (fis.read(headerBytes) != headerBytes.length || !ENCRYPTION_HEADER.equals(new String(headerBytes))) {
                System.out.println("File does not have the correct header or is not encrypted.");
                return;
            }

            byte[] salt = new byte[SALT_SIZE];
            if (fis.read(salt) != salt.length) {
                System.out.println("Could not read the salt from the file.");
                return;
            }

            SecretKey key = getKeyFromPassword(password, salt);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);

            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] output = cipher.update(buffer, 0, bytesRead);
                    if (output != null) fos.write(output);
                }
                byte[] output = cipher.doFinal();
                if (output != null) fos.write(output);
                System.out.println("Decryption complete.");
                failedAttempts = 0; // Reset failed attempts on successful decryption
            }
        } catch (Exception e) {
            failedAttempts++;
            System.out.println("Decryption failed. Attempt: " + failedAttempts);
            if (failedAttempts >= 10) {
                corruptFile(inputFile);
                failedAttempts = 0; // Reset after corruption
            }
            throw e;
        }
    }

    private static boolean isFileEncrypted(String filePath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String firstLine = reader.readLine();
            return firstLine != null && firstLine.contains(ENCRYPTION_HEADER);
        }
    }

    public static void main(String[] args) {
        if (args.length != 4) {
            System.out.println("Usage: java FileEncryptorDecryptorWithHeader <0 for decrypt/1 for encrypt> <file path> <output file> <password>");
            return;
        }

        int mode = Integer.parseInt(args[0]);
        String inputFile = args[1];
        String outputFile = args[2];
        String password = args[3];

        try {
            // encrypt
            if (mode == 1) {

                // Detecting file encryption status
                if (isFileEncrypted(inputFile)){
                    System.out.println("The file is encrypted, not re-encrypted");
                    return;
                }

                encrypt(password, inputFile, outputFile);

            }

            else if (mode == 0) {
                decrypt(password, inputFile, outputFile);

            } else {
                System.out.println("Invalid mode. Use 0 for decrypt and 1 for encrypt.");
            }
        } catch (Exception e) {
            System.out.println("An error occurred: " + e.getMessage());
        }
    }
}
