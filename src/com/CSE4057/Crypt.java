package com.CSE4057;

import javax.crypto.*;
import javax.crypto.spec.*;
//import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.*;
//import java.security.interfaces.RSAKey;
//import java.security.spec.EncodedKeySpec;
//import java.security.spec.InvalidKeySpecException;
//import java.security.spec.X509EncodedKeySpec;
import java.util.*;

// must implement Serializable in order to be sent
public class Crypt
{
    public Crypt() { }

    public static void main(String[] args) throws Exception
    {
    }

    public static byte[] encrypt(Key publicKeyOfClient, Key privateKeyOfServer) throws Exception	 // Encrypt Pub. Key of 'Client' with Pri. Key of 'Server'
    {
        Cipher encryptCipher = Cipher.getInstance("RSA");			// Cipher with 'RSA' mode
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKeyOfServer);	// Encrypt with Private Key of 'Server'
        byte[] cipherText = new byte[0];

        try{
            cipherText = encryptCipher.doFinal(publicKeyOfClient.getEncoded());			// Encrypt Cipher Text with Public Key of 'Client'
        }catch (Exception e){
            e.printStackTrace();
        }

        return cipherText;		// Return Cipher Text
    }

    public static Key decrypt(byte[] cipherText, Key publicKeyOfServer) throws Exception		// Decrypt Cipher Text with Pub. Key of 'Server'
    {
        byte[] bytes = Base64.getDecoder().decode(Base64.getEncoder().encodeToString(cipherText));
        Cipher decriptCipher = Cipher.getInstance("RSA");				// Decrypt Cipher with RSA mode
        decriptCipher.init(Cipher.DECRYPT_MODE, publicKeyOfServer); 	// Public Key of User1
        byte[] dec = decriptCipher.doFinal(bytes);

        Key a = new SecretKeySpec(dec, 0, dec.length, "RSA");

        return a;		// Return Decrypted Key
    }

    public byte[] encryptText(String toEncrypt, Key privateKey) throws Exception		// Encypt Text with Private Key
    {
        Cipher encryptCipher = Cipher.getInstance("RSA");		// Encrypt with RSA mode
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);	// Encrypt with Private Key
        byte[] cipherText = encryptCipher.doFinal(toEncrypt.getBytes());

        return cipherText;		// Return Cipher Text
    }

    public String decryptString(byte[] cipherText, Key publicKey) throws BadPaddingException, IllegalBlockSizeException		// Decrypt Text with Public Key
    {
        try {
            Cipher decriptCipher = Cipher.getInstance("RSA");		// Decrypt with RSA mode
            decriptCipher.init(Cipher.DECRYPT_MODE, publicKey); 	// Decrypt with Public Key (Public Key of User1)
            byte[] decStr = decriptCipher.doFinal(cipherText);

            return new String(decStr);		// Return Decrypted Text
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] macAlgorithm(SecretKey encryptionkey, byte[] message) throws Exception
    {
        // Created to be sure to Integrity Check
        Mac mac = Mac.getInstance("HmacMD5");		// MAC mode
        mac.init(encryptionkey);		// Initialize mac

        byte[] digest = mac.doFinal(message);		//  Finish the MAC Operation
        return digest;
    }

    public byte[] cbcBlockCipherEncrypt(byte[] message, byte[] ciphertext, SecretKey encryptionKey, IvParameterSpec iv) throws Exception
    {
        byte[] XORCipherText = messageXORcipherText(message, ciphertext);		// Create Cipher Text with XOR Method
        byte[] resultCipherText = getEncryptMessage(encryptionKey, iv, XORCipherText); // Sending Message will be applied XOR Operation
        return resultCipherText;
    }

    private byte[] getEncryptMessage(SecretKey encryptionKey, IvParameterSpec iv, byte[] XORciphertext) throws Exception
    {
        byte[] encryptedCipherText = null;
        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5PADDING");	  // Cipher Object for AES Encryption(CBC Mode)
        cipherAES.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);    		  // Initialize CIPHER for Encryption
        encryptedCipherText = cipherAES.doFinal(XORciphertext);
        return encryptedCipherText;
    }

    public byte[] cbcBlockCipherDecrypt(byte[] resultCipherText, byte[] ciphertext, SecretKey encryptionKey, IvParameterSpec iv) throws Exception
    {
        byte[] XORmessage = getDecryptMessage(encryptionKey, iv, resultCipherText);		// Decrypt the Ciphered Text
        byte[] message = messageXORcipherText(XORmessage, ciphertext);  // Coming message will pass XOR operation
        return message;
    }

    private byte[] getDecryptMessage(SecretKey encryptionKey, IvParameterSpec iv, byte[] resultciphertext) throws Exception
    {
        byte[] encryptedCipherText = null;
        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5PADDING");    // Cipher Object for AES Encryption(CBC Mode)
        cipherAES.init(Cipher.DECRYPT_MODE, encryptionKey, iv);    		  // Initialize CIPHER for Decryption
        encryptedCipherText = cipherAES.doFinal(resultciphertext);
        return encryptedCipherText;
    }

    public byte[] messageXORcipherText(byte[] message, byte[] ciphertext)
    {
        // Message is applied XOR operation with encrypted cipher
        // This method used for sending a message and getting a message
        byte[] XORCipherText = message;
        int i = 0, a = 0;
        for ( ; i < message.length; i++, a++) {
            XORCipherText[i] = (byte) (message[i] ^ ciphertext[a]);
            if (a == ciphertext.length - 1)
                a = 0;
        }
        // return XOR version of the message
        return XORCipherText;
    }

    public byte[] arrayConcatenate(byte[] message, byte[] macmessage, int nonce) throws UnsupportedEncodingException
    {
        // We concatenate Mac byte info, our message and nonce and provide Resistance to Replay Attacks
        String count = (macmessage.length + 1000000 + nonce) + ""; // 
        byte[] lengtMessage = count.getBytes("UTF-8");
        byte[] sendmessage = new byte[message.length + macmessage.length + lengtMessage.length];
        System.arraycopy(lengtMessage, 0, sendmessage, 0, lengtMessage.length);
        System.arraycopy(message, 0, sendmessage, lengtMessage.length, message.length);
        System.arraycopy(macmessage, 0, sendmessage, message.length + lengtMessage.length, macmessage.length);
        // Combined message will be sent
        return sendmessage;
    }

    public byte[] splityTheArray(byte[] clientmessage, SecretKey encryptionkey, int nonce) throws Exception
    {
        // We properly split comming array
        byte[] message = clientmessage;
        byte[] lengthmessage = new byte[7];
        for(int i = 0; i < 7; i++)
            lengthmessage[i] = message[i];
        // Split needed parameters
        int count = Integer.parseInt(new String(lengthmessage));
        int maclength = count - 1000000 - nonce;
        int messagelength = count - 1000000 - maclength - nonce;
        int takennonce = count - 1000000 - maclength - messagelength;

        byte[] takenmessage = new byte[message.length - 7 - maclength];
        byte[] takenmacmessage = new byte[maclength];

        System.arraycopy(message, 7, takenmessage, 0, takenmessage.length);
        System.arraycopy(message, 7 + takenmessage.length, takenmacmessage, 0, takenmacmessage.length);

        // To check mac message is right
        Boolean isright = checkMessageisRight(takenmacmessage, takenmessage, encryptionkey);

        return takenmessage;
    }

    private Boolean checkMessageisRight(byte[] macmessage, byte[] takenmessage, SecretKey encryptionkey) throws Exception
    {
        // To check mac message is right
        byte[] mac = macAlgorithm(encryptionkey, takenmessage);
        boolean ret = Arrays.equals(mac, macmessage);
        return ret;
    }

}
