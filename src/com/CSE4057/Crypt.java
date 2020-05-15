package com.CSE4057;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

// must implement Serializable in order to be sent
public class Crypt {

    public Crypt() {

    }
    public static void main(String[] args) throws Exception{
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        Key publicKeyOfClient = kp.getPublic();
        Key privateKeyOfClient = kp.getPrivate();

        KeyPairGenerator kpg1 = KeyPairGenerator.getInstance("RSA");
        kpg1.initialize(4096);
        kp = kpg1.generateKeyPair();
        Key publicKeyOfServer = kp.getPublic();
        Key privateKeyOfServer = kp.getPrivate();

        KeyPairGenerator kpg2 = KeyPairGenerator.getInstance("RSA");
        kpg2.initialize(2048);
        Key publicKeyOfSecondClient = kp.getPublic();
        Key privateKeyOfSecondClient = kp.getPrivate();

        System.out.println("---"+Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()));
        byte[] cipherText = encrypt(publicKeyOfClient,privateKeyOfServer);
        Key publi = decrypt(cipherText,publicKeyOfServer);
        System.out.println("---"+Base64.getEncoder().encodeToString(publi.getEncoded()));

//        if(Base64.getEncoder().encodeToString(publi.getEncoded()).equals(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded())))
//            System.out.println("Doğru");


    }
    public static byte[] encrypt(Key publicKeyOfClient, Key privateKeyOfServer) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");

        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKeyOfServer);

        byte[] cipherText = new byte[0];
        try{
            cipherText = encryptCipher.doFinal(publicKeyOfClient.getEncoded());
        }catch (Exception e){
            e.printStackTrace();
        }

        return cipherText;
    }
    public static Key decrypt(byte[] cipherText , Key publicKeyOfServer) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(Base64.getEncoder().encodeToString(cipherText));
        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, publicKeyOfServer); // public key of user1
        byte[] dec = decriptCipher.doFinal(bytes);

        Key a = new SecretKeySpec(dec, 0, dec.length, "RSA");
        return a;
    }

    public byte[] encryptText(String toEncrypt, Key privateKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] cipherText = encryptCipher.doFinal(toEncrypt.getBytes());
        return cipherText;
    }

    public String decryptString(byte[] cipherText,Key publicKey) throws BadPaddingException, IllegalBlockSizeException {
        try {
            Cipher decriptCipher = Cipher.getInstance("RSA");;
            decriptCipher.init(Cipher.DECRYPT_MODE, publicKey); // public key of user1
            byte[] decStr = decriptCipher.doFinal(cipherText);
            return new String(decStr);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] MacAlgorithm(SecretKey encryptionkey, byte[] message) throws Exception {

        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(encryptionkey);

        byte[] digest = mac.doFinal(message);
        return digest;
    }

    public byte[] cbcBlockCipherEncrypt(byte[] message, byte[] ciphertext, SecretKey encryptionKey, IvParameterSpec iv) throws Exception {
        byte[] XORCipherText = MessageXORcipherText(message,ciphertext);
        byte[] resultCipherText = getEncryptMessage(encryptionKey,iv,XORCipherText);
        return resultCipherText;
    }

    private byte[] getEncryptMessage(SecretKey encryptionKey, IvParameterSpec iv,byte[] XORciphertext) throws Exception{
        byte[] encryptedCipherText = null;
        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipherAES.init(Cipher.ENCRYPT_MODE, encryptionKey,iv);    // initialize CIPHER for encryption.
        encryptedCipherText = cipherAES.doFinal(XORciphertext);
        return encryptedCipherText;
    }

    public byte[] cbcBlockCipherDecrypt(byte[] resultCipherText, byte[] ciphertext,SecretKey encryptionKey, IvParameterSpec iv) throws Exception {
        byte[] XORmessage = getDecryptMessage(encryptionKey,iv,resultCipherText);
        byte[] message    = MessageXORcipherText(XORmessage,ciphertext);
        return message;
    }

    private byte[] getDecryptMessage(SecretKey encryptionKey, IvParameterSpec iv,byte[] resultciphertext) throws Exception {
        byte[] encryptedCipherText = null;
        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipherAES.init(Cipher.DECRYPT_MODE, encryptionKey,iv);    // initialize CIPHER for encryption.
        encryptedCipherText = cipherAES.doFinal(resultciphertext);
        return encryptedCipherText;
    }

    public byte[] MessageXORcipherText(byte[] message, byte[] ciphertext){

        byte[] XORCipherText = message;
        int i = 0, a = 0;
        for ( ; i < message.length ; i++,a++) {
            XORCipherText[i] = (byte) (message[i]^ ciphertext[a]);
            if (a == ciphertext.length-1)
                a = 0;
        }
        return XORCipherText;
    }

    public byte[] arrayConcatanate(byte[] message, byte[] macmessage,int nonce) throws UnsupportedEncodingException {
        String count = (macmessage.length+1000000+nonce)+"";
        byte[] lengtMessage = count.getBytes("UTF-8");
//        System.out.println(lengtMessage.length);
//        System.out.println(new String(lengtMessage));
        byte[] sendmessage = new byte[message.length + macmessage.length+lengtMessage.length];
        System.arraycopy(lengtMessage, 0, sendmessage, 0, lengtMessage.length);
        System.arraycopy(message, 0, sendmessage, lengtMessage.length, message.length);
        System.arraycopy(macmessage, 0, sendmessage, message.length+lengtMessage.length, macmessage.length);
//        System.out.println(new String(sendmessage));
        return sendmessage;
    }

    public byte[] splityTheArray(byte[] clientmessage,SecretKey encryptionkey,int nonce) throws Exception {
        byte[] message = clientmessage;
        byte[] lengthmessage = new byte[7];
        for(int i=0;i<7;i++)
            lengthmessage[i] = message[i];
        int count = Integer.parseInt(new String(lengthmessage));
        int maclength = count - 1000000-nonce;
        int messagelength = count-1000000-maclength-nonce;
        int takennonce = count-1000000 - maclength-messagelength;


        byte[] takenmessage = new byte[message.length-7-maclength]; byte[] takenmacmessage = new byte[maclength];

        System.arraycopy(message, 7, takenmessage, 0, takenmessage.length);
        System.arraycopy(message, 7+takenmessage.length, takenmacmessage, 0, takenmacmessage.length);

        Boolean isright =  checkMessageisRight(takenmacmessage,takenmessage,encryptionkey);
//        if (isright)
//            System.out.println("====================================Dogru mesaj Bro================");
//        if (takennonce==nonce)
//            System.out.println("====================================Dogru Nonce Bro================");
        return takenmessage;
    }

    private Boolean checkMessageisRight(byte[] macmessage,byte[] takenmessage,SecretKey encryptionkey) throws Exception {
        byte[] mac = MacAlgorithm(encryptionkey,takenmessage);
        boolean ret = Arrays.equals(mac, macmessage);
        return ret;
    }

}
