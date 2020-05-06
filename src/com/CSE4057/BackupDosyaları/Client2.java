package com.CSE4057.BackupDosyaları;

// Java implementation for a client
// Save file as Client.java

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Scanner;

// Client class
public class Client2
{

    private Key pub,pvt;
    private String userName="";
    private KeyPairGenerator kpg;
    private KeyPair kp;
    private Client2() throws Exception {
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


    public static void main(String[] args) throws IOException
    {
        try
        {
            Scanner scn = new Scanner(System.in);

            // getting localhost ip
            InetAddress ip = InetAddress.getByName("localhost");

            // establish the connection with server port 8018
            Socket s = null;
            try{
                s = new Socket(ip, 8018);
            }
            catch (Exception e){
                System.out.println("Can not reach the server");
                return;
            }

            // obtaining input and out streams
            DataInputStream dis = new DataInputStream(s.getInputStream());
            DataOutputStream dos = new DataOutputStream(s.getOutputStream());

            // the following loop performs the exchange of
            // information between client and client handler
            while (true)
            {
                System.out.println(dis.readUTF());
                String tosend = scn.nextLine();
                dos.writeUTF(tosend);

                // If client sends exit,close this connection
                // and then break from the while loop
                if(tosend.equals("Exit"))
                {
                    System.out.println("Closing this connection : " + s);
                    s.close();
                    System.out.println("Connection closed");
                    break;
                }

                // printing date or time as requested by client
                String received = dis.readUTF();
                System.out.println(received);
            }

            // closing resources
            scn.close();
            dis.close();
            dos.close();
        }catch(Exception e){
            e.printStackTrace();
//            System.out.println("Server reset by peer");
        }
    }
}
