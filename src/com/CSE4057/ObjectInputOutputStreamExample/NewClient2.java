package com.CSE4057.ObjectInputOutputStreamExample;


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

public class NewClient2 {
    private static Key pub;
    private static Key pvt;
    private static String userName="";
    public static byte[] serverCertificate = null;
    public static Key serverPublicKey = null;
    public static Boolean verifyCheck = false;
    public static boolean scannerOn;

    public NewClient2() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();
        //defined key pair; public and private and we generate new pair
        this.pub = kp.getPublic();
        this.pvt = kp.getPrivate();
        this.userName="";
        verifyCheck = false;
        this.serverCertificate = null;
        this.serverPublicKey = null;
        System.out.println("Client generate its keys");
        boolean scannerOn=false;
    }
    public void setPublicKey(Key k){
        pub=k;
    }
    public void setPrivateKey(Key k){
        pvt=k;
    }
    public void setUserName(String name){userName=name;}
    public static Key getPublicKey(){return pub;}
    public Key getPrivateKey(){return pvt;}
    public String getUserName() {return userName;    }
    public static Key getServerPublicKey(){return serverPublicKey;}

    public static void main(String[] args) throws Exception {

        NewClient2 client = new NewClient2();

        Scanner scn = new Scanner(System.in);
        String name = null;

        System.out.println("Enter username : ");
        while(name == null  || name =="" ){
            name = scn.nextLine();
            client.setUserName(name);
        }
        System.out.println("Client ready to connect server ...");
//        System.out.println(client.getUserName());
        // need host and port, we want to connect to the ServerSocket at port 7777
        Socket socket = new Socket("localhost", 8018);

        // create an object output stream from the output stream so we can send an object through it
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());

        System.out.println("Sending public key and username to the ServerSocket");
        objectOutputStream.writeObject(client.getPublicKey());
        objectOutputStream.writeObject(client.getUserName());
//        scannerOn = true;
        System.out.println("Scanner on "+scannerOn);
        HashMap allPeers=null;
        client.scannerOn=false;
        while (true){
            Object o = objectInputStream.readObject();
            if (o instanceof byte[]){
                System.out.println("Certificate come");
                serverCertificate = (byte[]) o;
                verifyCheck = true;
            } else if (o instanceof Key){
                System.out.println("Key come");
                serverPublicKey = (Key) o;
                verifyCheck = true;
            } else if (o == null){
                System.out.println("Coming object is null");
            } else if (o instanceof HashMap){
                Crypt crypt = new Crypt();
                allPeers = (HashMap) o;
                allPeers.forEach((key, value) -> {
                    try {
                        System.out.println(key+" "+crypt.decrypt((byte[]) value,getServerPublicKey()));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            } else if (o instanceof String){
                System.out.println("Message come");
                System.out.println(o.toString());
            }
            if (verifyCheck && serverPublicKey != null && serverCertificate != null){
                String verify = verifySigniture(serverCertificate,serverPublicKey);
                objectOutputStream.writeObject(verify);
                verifyCheck = false;
                scannerOn = true;
            }
            if(scannerOn){
                System.out.println("Enter your choice\n1. send all peers\n");
                String command = scn.nextLine();
                objectOutputStream.writeObject(command);
            }


        }
    }

    private static String verifySigniture(byte[] serverSigniture, Key serverPublicKey) throws Exception {
        String verify = "verified certificate";
        String notVerifyed ="not verified certificate";
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify((PublicKey) getServerPublicKey() );
        s.update(Base64.getEncoder().encodeToString(getPublicKey().getEncoded()).getBytes());

        if(s.verify(serverCertificate)){
            return verify;
        }else
            return notVerifyed;

    }
    private static Key getClientPublicKey(String certificate,Key publicKeyOfServer) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(certificate);
        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, publicKeyOfServer); // public key of user1
        byte[] dec = decriptCipher.doFinal(bytes);
        Key publicKeyOfOneClient = new SecretKeySpec(dec, 0, dec.length, "RSA");
        System.out.println(Base64.getEncoder().encodeToString(publicKeyOfOneClient.getEncoded()));
        return publicKeyOfOneClient;
    }
}

