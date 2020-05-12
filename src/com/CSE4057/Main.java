package com.CSE4057;

import com.CSE4057.ObjectInputOutputStreamExample.Crypt;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Main {

    public static void main(String[] args) throws Exception {


        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();
        Key publicKeyOfClient = kp.getPublic();
        Key privateKeyOfClient = kp.getPrivate();


        KeyPairGenerator kpg1 = KeyPairGenerator.getInstance("RSA");
        kpg1.initialize(512);
        kp = kpg1.generateKeyPair();
        Key publicKeyOfServer = kp.getPublic();
        Key privateKeyOfServer = kp.getPrivate();

        KeyPairGenerator kpg2 = KeyPairGenerator.getInstance("RSA");
        kpg2.initialize(2048);
        Key publicKeyOfSecondClient = kp.getPublic();
        Key privateKeyOfSecondClient = kp.getPrivate();


//        Crypt crypt = new Crypt();
//        crypt.encrypt();
//
//

//        Signature s = Signature.getInstance("SHA256withRSA");
//        s.initSign((PrivateKey) privateKeyOfServer);
//        s.update(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()).getBytes());
//        byte[] digitalSign = s.sign();
//        System.out.println(Base64.getEncoder().encodeToString(digitalSign));
//
//
//        s.initVerify((PublicKey) publicKeyOfServer);
//        s.update(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()).getBytes());
//        if(s.verify(digitalSign)){
//            System.out.println("Verified with public key");
//        }else
//            System.out.println("Not verified");


//        System.out.println(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()));
//        Cipher encryptCipher = Cipher.getInstance("RSA");
//        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKeyOfServer);
//        byte[] cipherText = encryptCipher.doFinal(publicKeyOfClient.getEncoded());
//        System.out.println(Base64.getEncoder().encodeToString(cipherText));
//
//
//
//        byte[] bytes = Base64.getDecoder().decode(Base64.getEncoder().encodeToString(cipherText));
//        Cipher decriptCipher = Cipher.getInstance("RSA");
//        decriptCipher.init(Cipher.DECRYPT_MODE, publicKeyOfServer); // public key of user1
//        byte[] dec = decriptCipher.doFinal(bytes);
//        Key a = new SecretKeySpec(dec, 0, dec.length, "RSA");
//        System.out.println(Base64.getEncoder().encodeToString(a.getEncoded()));




//        Cipher encryptCipher = Cipher.getInstance("RSA");
//        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKeyOfClient);
//        byte[] cipherText = encryptCipher.doFinal("9".getBytes(UTF_8));
//        System.out.println(Base64.getEncoder().encodeToString(cipherText));
//
//
//
//        byte[] bytes = Base64.getDecoder().decode(Base64.getEncoder().encodeToString(cipherText));
//        Cipher decriptCipher = Cipher.getInstance("RSA");
//        decriptCipher.init(Cipher.DECRYPT_MODE, publicKeyOfClient); // public key of user1
//        System.out.println(new String(decriptCipher.doFinal(bytes), UTF_8));




//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, privateKeyOfClient);
//        cipher.update(Base64.getEncoder().encodeToString("9".getBytes()).getBytes());
//        byte[] enc= cipher.doFinal();
//        System.out.println("encypted with private key : "+Base64.getEncoder().encodeToString(enc));
//
//
//        cipher.init(Cipher.DECRYPT_MODE,);
//        byte[] decipheredText = cipher.doFinal(enc);
//        System.out.println("128-bit symmetric key decrypted version : "+new String(decipheredText)+"\n");



//        System.out.println(Base64.getEncoder().encodeToString(publicKeyOfServer.getEncoded()));
//        System.out.println(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()));
//
//        Signature s = Signature.getInstance("SHA256withRSA");
//        s.initSign((PrivateKey) privateKeyOfServer);
//        s.update(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()).getBytes());
//
//        byte[] digitalSign = s.sign();
//        System.out.println(Base64.getEncoder().encodeToString(digitalSign));
//
//        s.initVerify((PublicKey) publicKeyOfServer);
//        s.update(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()).getBytes());
//
//        if(s.verify(digitalSign)){
//            System.out.println("Verified with public key");
//        }else
//            System.out.println("Not verified");



    }


}
