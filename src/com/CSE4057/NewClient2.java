//package com.CSE4057;
//
//
//import java.io.ObjectInputStream;
//import java.io.ObjectOutputStream;
//import java.net.Socket;
//import java.security.Key;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.cert.Certificate;
//import java.util.Scanner;
//
//public class NewClient2 {
//    private Key pub,pvt;
//    private String userName="";
//    private KeyPairGenerator kpg;
//    private KeyPair kp;
//    private static Certificate serverCertificate = null;
//    private static Key serverPublicKey = null;
//    private static Boolean verifyCheck = false;
//    private NewClient2() throws Exception {
//        kpg = KeyPairGenerator.getInstance("RSA");
//        kpg.initialize(2048);
//        kp = kpg.generateKeyPair();
//        //defined key pair; public and private and we generate new pair
//        pub = kp.getPublic();
//        pvt = kp.getPrivate();
//        System.out.println("Client generate its keys");
//    }
//    public void setPublicKey(Key k){
//        pub=k;
//    }
//    public void setPrivateKey(Key k){
//        pvt=k;
//    }
//    public void setUserName(String name){userName=name;}
//    public Key getPublicKey(){return pub;}
//    public Key getPrivateKey(){return pvt;}
//    public String getUserName() {return userName;    }
//
//    public static void main(String[] args) throws Exception {
//
//        NewClient2 client = new NewClient2();
//        Scanner scn = new Scanner(System.in);
//        String name = null;
//
//        System.out.println("Enter username : ");
//        while(name == null  || name =="" ){
//            name = scn.nextLine();
//            client.setUserName(name);
//        }
//        System.out.println("Client ready to connect server ...");
//
//        // need host and port, we want to connect to the ServerSocket at port 7777
//        Socket socket = new Socket("localhost", 8018);
//
//        // create an object output stream from the output stream so we can send an object through it
//        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
//        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
//
//        System.out.println("Sending messages to the ServerSocket");
//        objectOutputStream.writeObject(client.getPublicKey());
//        objectOutputStream.writeObject(client.getUserName());
//
//        System.out.println("Closing socket and terminating program.");
//        while (true){
//            Object o = objectInputStream.readObject();
//            if (o instanceof Certificate){
//                System.out.println("Certificate come");
//                serverCertificate = (Certificate) o;
//                verifyCheck = true;
//            } else if (o instanceof Key){
//                System.out.println("Key come");
//                serverPublicKey = (Key) o;
//                verifyCheck = true;
//            } else if (o == null){
//                System.out.println("Coming object is null");
//            }
//            if (verifyCheck && serverPublicKey != null && serverCertificate != null){
//                String verify = verifySigniture(serverCertificate,serverPublicKey);
//                objectOutputStream.writeObject(verify);
//                verifyCheck = false;
//            }
//
//        }
//    }
//
//    private static String verifySigniture(Certificate serverSigniture, Key serverPublicKey) {
//        //burada verify edersin
//        String verify = "verified certificate";
//        String notVerifyed ="not verified certificate";
//
//
//        //verify edemezse not verified gönderirsin
//        return verify;
//    }
//}
//
