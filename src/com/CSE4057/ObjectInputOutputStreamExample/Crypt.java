package com.CSE4057.ObjectInputOutputStreamExample;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

        if(Base64.getEncoder().encodeToString(publi.getEncoded()).equals(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded())))
            System.out.println("Doğru");


    }
    public static byte[] encrypt(Key publicKeyOfClient, Key privateKeyOfServer) throws Exception {
//        System.out.println(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()));
        Cipher encryptCipher = Cipher.getInstance("RSA");

        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKeyOfServer);

        byte[] cipherText = new byte[0];
        try{
//            System.out.println(publicKeyOfClient.getEncoded().length);
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
//        System.out.println(Base64.getEncoder().encodeToString(a.getEncoded()));

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
//            System.out.println("Ne bu şimdi yaa");
            e.printStackTrace();
        }
        return null;
    }
}
