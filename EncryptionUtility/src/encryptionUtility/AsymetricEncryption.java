package encryptionUtility;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;

public class AsymetricEncryption {
    private static final String ENCRYPTION_ALGORITHM = "RSA"; //Encryption Alg
    private static final int KEY_SIZE = 2048; 				  //Key Length

    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPair keyPair = generateRSAKeyPair();

        // Get public and private keys
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Original text
        String originalText = readFromFile("password.txt");

        // Encrypt the original text using the public key
        byte[] encryptedData = encrypt(originalText, publicKey);
        
        writeToFile(encryptedData, "encrypted.txt");

        // Decrypt the encrypted data using the private key
        String decryptedText = decrypt(encryptedData, privateKey);
        
        writeToFile(decryptedText, "decrypted.txt");
        
        // Print the public key
        System.out.print("Public Key:");
        System.out.print(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        // Print the private key
        System.out.print("\nPrivate Key:");
        System.out.print(Base64.getEncoder().encodeToString(privateKey.getEncoded()));

        System.out.println("\nOriginal Text: " + originalText);
        System.out.println("Encrypted Text: " + Base64.getEncoder().encodeToString(encryptedData));
        System.out.println("Decrypted Text: " + decryptedText);
    }

    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ENCRYPTION_ALGORITHM);            // Create an instance of KeyPairGenerator for RSA
        keyPairGenerator.initialize(KEY_SIZE);															   //Initialiuze KP w Size
        return keyPairGenerator.generateKeyPair();														   //Generate RSA KP
    }

    public static byte[] encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);											//Create Cipher w RSA
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);														//Initialize with public key 
        return cipher.doFinal(plainText.getBytes());														//Encrypt txt and return encrypted bytes
    }

    public static String decrypt(byte[] cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);										
        cipher.init(Cipher.DECRYPT_MODE, privateKey);														//initialize with private key
        byte[] decryptedBytes = cipher.doFinal(cipherText);													//Decrypt and convert to string 
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