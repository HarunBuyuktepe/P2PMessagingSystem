package com.CSE4057.ObjectInputOutputStreamExample;


import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.util.Scanner;

public class NewClient2 {
    private static Key pub;
    private static Key pvt;
    private static String userName="";
    private static KeyPairGenerator kpg;
    private static KeyPair kp;
    private static Certificate serverCertificate = null;
    private static Key serverPublicKey = null;
    private static Boolean verifyCheck = false;

    public static void main(String[] args) throws Exception {

        NewClient client = new NewClient();
        Scanner scn = new Scanner(System.in);
        String name = null;

        System.out.println("Enter username : ");
        while(name == null  || name =="" ){
            name = scn.nextLine();
            client.setUserName(name);
        }
        System.out.println("Client ready to connect server ...");

        // need host and port, we want to connect to the ServerSocket at port 7777
        Socket socket = new Socket("localhost", 8018);

        // create an object output stream from the output stream so we can send an object through it
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());

        System.out.println("Sending messages to the ServerSocket");
        objectOutputStream.writeObject(client.getPublicKey());
        objectOutputStream.writeObject(client.getUserName());

        System.out.println("Closing socket and terminating program.");
        while (true){
            Object o = objectInputStream.readObject();
            if (o instanceof Certificate){
                System.out.println("Certificate come");
                serverCertificate = (Certificate) o;
                verifyCheck = true;
            } else if (o instanceof Key){
                System.out.println("Key come");
                serverPublicKey = (Key) o;
                verifyCheck = true;
            } else if (o == null){
                System.out.println("Coming object is null");
            }
            if (verifyCheck && serverPublicKey != null && serverCertificate != null){
                String verify = verifySigniture(serverCertificate,serverPublicKey);
                objectOutputStream.writeObject(verify);
                verifyCheck = false;
            }

        }
    }

    private static String verifySigniture(Certificate serverSigniture, Key serverPublicKey) {
        //burada verify edersin
        String verify = "verified certificate";
        String notVerifyed ="not verified certificate";


        //verify edemezse not verified gönderirsin
        return verify;
    }
}

