package com.CSE4057.ObjectInputOutputStreamExample;


import com.CSE4057.ObjectInputOutputStreamExample.ClientHandler;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;


public class NewServer {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        // don't need to specify a hostname, it will be the current machine
        ServerSocket ss = new ServerSocket(8018);
        System.out.println("ServerSocket awaiting connections...");

        while (true) {
            Socket s = null;

            try {
                s = ss.accept(); // blocking call, this will wait until a connection is attempted on this port.
                System.out.println("A new client is connected : " + s.getPort());

                // create a DataInputStream so we can read data from it.
                ObjectInputStream objectInputStream = new ObjectInputStream(s.getInputStream());
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(s.getOutputStream());

                System.out.println("Assigning new thread for this client");
                // create a new thread object
                Thread t = new ClientHandler(s, objectInputStream, objectOutputStream);

                t.start();

            } catch (Exception e) {
                System.out.println("olmii");
            }
        }

    }
}

// ClientHandler class
class ClientHandler extends Thread
{
    final ObjectInputStream ois;
    final ObjectOutputStream oos;
    final Socket s;


    // Constructor
    public ClientHandler(Socket s, ObjectInputStream ois, ObjectOutputStream oos)
    {
        this.s = s;
        this.ois = ois;
        this.oos = oos;
    }

    @Override
    public void run()
    {
        Key publicKey = null;
        try {
            publicKey = (Key) ois.readObject();
        } catch (Exception e) {
            System.out.println("Neden olmuyor arkadaş");
        }
        System.out.println(publicKey);


    }
}
