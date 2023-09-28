package encryptionUtility;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;

public class SymmetricEncryption {
    private static final String ENCRYPTION_ALGORITHM = "AES";								//Encryption Alg
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";					//key Derivative 
    private static final int ITERATIONS = 10000;											//Iterations
    private static final int KEY_LENGTH = 256;												//key length
    
    
    public static void main(String[] args) throws Exception {
    	 // Read the original text from a file
        String originalText = readFromFile("password.txt");
        char[] password = "MySecretPassword".toCharArray();
        byte[] salt = new byte[16]; // Generate or store a secure salt

        SecretKey secretKey = generateSecretKey(password, salt);

        byte[] encryptedData = encrypt(originalText, secretKey);
 
        // Write the encrypted data to a file
        writeToFile(encryptedData, "encrypted.txt");

        // Read the encrypted data from a file
        byte[] encryptedDataFromFile = readBytesFromFile("encrypted.txt");

        String decryptedText = decrypt(encryptedDataFromFile, secretKey);

        // Write the decrypted text to a file
        writeToFile(decryptedText, "decrypted.txt");

        System.out.println("Original Text: " + originalText);
        System.out.println("Encrypted Text: " + encryptedData);
        System.out.println("Decrypted Text: " + decryptedText);
    }

    public static SecretKey generateSecretKey(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(HASH_ALGORITHM);			//Initialize SKF to the key derivative
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);		//Initialize PBEKS with pass, salt, iterations, and length
        SecretKey secretKey = keyFactory.generateSecret(keySpec);							//Generate SK using PBEKS
        return new SecretKeySpec(secretKey.getEncoded(), ENCRYPTION_ALGORITHM);				//Convert SKS back to SKS format
    }

    public static byte[] encrypt(String plainText, SecretKey secretKey) throws Exception {	
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);							//Create Cipher using AES
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);										//Init using encryption code  and SK
        return cipher.doFinal(plainText.getBytes());										//Encrypt to plain text/byte[]
    }

    public static String decrypt(byte[] cipherText, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);							//Create Cipher using AES
        cipher.init(Cipher.DECRYPT_MODE, secretKey);										//init cipher with decryption code and SK
        byte[] decryptedBytes = cipher.doFinal(cipherText);									//Decrypt to plain text/byte[]
        return new String(decryptedBytes);
    }

    /*-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
     * Basic read/write functions
     ------------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
    public static String readFromFile(String filePath) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(filePath));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();
        return content.toString();
    }

    public static void writeToFile(String data, String filePath) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(filePath));
        writer.write(data);
        writer.close();
    }

    public static byte[] readBytesFromFile(String filePath) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(filePath);
        byte[] data = fileInputStream.readAllBytes();
        fileInputStream.close();
        return data;
    }

    public static void writeToFile(byte[] data, String filePath) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(filePath);
        fileOutputStream.write(data);
        fileOutputStream.close();
    }
}
