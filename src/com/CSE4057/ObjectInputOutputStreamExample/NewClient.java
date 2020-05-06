package com.CSE4057.ObjectInputOutputStreamExample;



import java.io.*;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class NewClient {
    private Key pub,pvt;
    private String userName="";
    private KeyPairGenerator kpg;
    private KeyPair kp;
    private NewClient() throws Exception {
        kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kp = kpg.generateKeyPair();
        //defined key pair; public and private and we generate new pair
        pub = kp.getPublic();
        pvt = kp.getPrivate();
        System.out.println("Client generate its keys");
    }
    public void setPublicKey(Key k){
        pub=k;
    }
    public void setPrivateKey(Key k){
        pvt=k;
    }
    public void setUserName(String name){userName=name;}
    public Key getPublicKey(){return pub;}
    public Key getPrivateKey(){return pvt;}
    public String getUserName() {return userName;    }

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


        System.out.println("Sending messages to the ServerSocket");
        objectOutputStream.writeObject(client.getPublicKey());

        System.out.println("Closing socket and terminating program.");
        socket.close();
    }
}

