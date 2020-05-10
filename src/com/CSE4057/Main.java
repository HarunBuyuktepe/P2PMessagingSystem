package com.CSE4057;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Main {

    public static void main(String[] args) throws Exception {


        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        Key publicKeyOfClient = kp.getPublic();
        Key privateKeyOfClient = kp.getPrivate();

        KeyPairGenerator kpg1 = KeyPairGenerator.getInstance("RSA");
        kpg1.initialize(2048);
        kp = kpg1.generateKeyPair();
        Key publicKeyOfServer = kp.getPublic();
        Key privateKeyOfServer = kp.getPrivate();

        System.out.println(Base64.getEncoder().encodeToString(publicKeyOfServer.getEncoded()));
        System.out.println(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()));

        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign((PrivateKey) privateKeyOfServer);
        s.update(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()).getBytes());

        byte[] digitalSign = s.sign();
        System.out.println(Base64.getEncoder().encodeToString(digitalSign));

        s.initVerify((PublicKey) publicKeyOfServer);
        s.update(Base64.getEncoder().encodeToString(publicKeyOfClient.getEncoded()).getBytes());

        if(s.verify(digitalSign)){
            System.out.println("Verified with public key");
        }else
            System.out.println("Not verified");



    }


}
