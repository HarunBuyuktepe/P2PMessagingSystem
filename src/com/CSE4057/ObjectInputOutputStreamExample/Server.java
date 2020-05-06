package com.CSE4057.ObjectInputOutputStreamExample;


import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.List;

public class Server {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        // don't need to specify a hostname, it will be the current machine
        ServerSocket s = new ServerSocket(8018);
        System.out.println("ServerSocket awaiting connections...");
        Socket socket = s.accept(); // blocking call, this will wait until a connection is attempted on this port.
        System.out.println("A new client is connected : " + socket.getPort());

        // get the input stream from the connected socket
        InputStream inputStream = socket.getInputStream();
        // create a DataInputStream so we can read data from it.
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

        // read the list of messages from the socket
        Key publicKey = (Key) objectInputStream.readObject();
        System.out.println(publicKey);
        // print out the text of every message

        System.out.println("Closing sockets.");
        s.close();
        socket.close();
    }
}