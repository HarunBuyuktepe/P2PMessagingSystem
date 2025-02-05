package com.CSE4057;

import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;

import static com.CSE4057.NewClient.verifySigniture;

public class NewClient2
{
    public static void main(String[] args) throws Exception
    {
        NewClient client = new NewClient();
        client.portNumber = 8034;		// Port Number of Client2
        ServerSocket ss ;
        Scanner scn = new Scanner(System.in);
        String name = null;

        System.out.print("Enter Username : ");
        while (name == null || name == "") {
            name = scn.nextLine();
            client.setUserName(name);
        }
        
        System.out.println("Client ready to connect server ...");
        Socket socket = new Socket("localhost", 8018);				// Socket Object with its Port Number (8018)
        client.socketList.add(socket);
        
        // create an object output stream from the output stream so we can send an object through it
        ObjectOutputStream serverObjectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream serverObjectInputStream = new ObjectInputStream(socket.getInputStream());

        System.out.println("Sending Public Key & Username to the ServerSocket");
        serverObjectOutputStream.writeObject(client.getPublicKey());
        serverObjectOutputStream.writeObject(client.getUserName());
        serverObjectOutputStream.writeObject(client.getPortNumber());

        int portToConnect = 0;
        HashMap allPeers = null;
        HashMap portPeers = null;
        client.scannerOn = false;
        client.wait = true;
        
        while (true)
        {
            Object o = serverObjectInputStream.readObject();
            if (o instanceof byte[]) {
                System.out.println("Certificate come");
                client.serverCertificate = (byte[]) o;
                client.verifyCheck = true;
            } 
            else if (o instanceof Key) {
                System.out.println("Key come");
                client.serverPublicKey = (Key) o;
                client.verifyCheck = true;
            } 
            else if (o == null) {
                System.out.println("Coming object is null");
            } 
            else if (o instanceof HashMap) {
                Crypt crypt = new Crypt();
                HashMap anyhash = (HashMap) o;
                Map.Entry entry = (Map.Entry) anyhash.entrySet().iterator().next();
                if (entry.getValue() instanceof byte[]) {
                    allPeers = anyhash;
                    client.wait = true;
                } else {
                    portPeers = anyhash;
                    portPeers.forEach((key, value) -> {
                        try {
                            System.out.println("Peer : " + key + " Available Port : " + value);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
                    client.wait = false;
                }
            } 
            else if (o instanceof String) {
                System.out.println("Message come");
                System.out.println(o.toString());
            }
            
            if (client.verifyCheck && client.serverPublicKey != null && client.serverCertificate != null) {
                String verify = client.verifySigniture(client.serverCertificate, client.serverPublicKey);
                serverObjectOutputStream.writeObject(verify);
                client.verifyCheck = false;
                client.scannerOn = true;
                client.wait = false;
            }
            
            if (client.scannerOn && !client.wait) {
                System.out.println("Enter your choice\n1.To get all peer certificate and username, - send all peers" +
                        "\n2.To connect user, - connect USERNAME\n3.To terminate server connection, - terminate server connection");
                String command = scn.nextLine();
                if (command.contains("terminate server connection")) {
                    socket.close();
                    break;
                }  
                else if (command.contains("connect ")) {
                    String connect = "";
                    try {
                        connect = (command.replace("connect ", ""));
                    } catch (Exception e) {
                        System.out.println("hata");
                    }
                    if (portPeers != null) {
                        portToConnect = (int) portPeers.get(connect);
                        for (Socket s : client.socketList) {
                            if (s.getPort() == portToConnect) {
                                s.close();
                                System.out.println("Selected port closed");
                            }
                        }
                        System.out.println("Server connection was closed...");
                        socket.close();
                        break;
                    }
                } 
                else 
                    serverObjectOutputStream.writeObject(command);

            }
        }
        
        if (portToConnect != 0) {
            System.out.println("Port to connect : " + portToConnect);
            Socket toPeerSocket = new Socket("localhost", portToConnect);
            client.socketList.add(toPeerSocket);
            ObjectOutputStream clientObjectOutputStream = new ObjectOutputStream(toPeerSocket.getOutputStream());
            ObjectInputStream clientObjectInputStream = new ObjectInputStream(toPeerSocket.getInputStream());

            clientObjectOutputStream.writeObject(new String("Hello"));
            clientObjectOutputStream.writeObject(client.serverCertificate);
            clientObjectOutputStream.writeObject(new String("username "+client.getUserName()));
            clientObjectOutputStream.writeObject(client.getPublicKey());

            Thread t = new PeerUserOneHandler(toPeerSocket, clientObjectInputStream, clientObjectOutputStream,client);
            t.start();
        }
        
        System.out.println("Program end");
        try {
            ss = new ServerSocket(client.portNumber);
            while (true) {
                try {
                    System.out.println("Wait for any connection");
                    socket = ss.accept();
                    client.socketList.add(socket);
                    ObjectInputStream serverClientObjectInputStream = new ObjectInputStream(socket.getInputStream());
                    ObjectOutputStream serverClientObjectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                    Thread t = new PeerUserTwoHandler(socket, serverClientObjectInputStream, serverClientObjectOutputStream, client);
                    t.start();
                    System.out.println("Accepted");
                } catch (Exception e) {
//                    System.out.println("Olmii");
                }
            }

        }
        catch (Exception e){
            e.printStackTrace();
            System.out.println("Hata");
        }
    }
}

// PeerHandler class
class PeerUserTwoHandler extends Thread
{
    // final ObjectInputStream ois;
	// final ObjectOutputStream oos;
    final Socket s;
    // create a DataInputStream so we can read data from it.
    ObjectInputStream objectInputStream = null;
    ObjectOutputStream objectOutputStream = null;
    String userNameOfClient = null;
    byte[] certificateOfnewPeer = null;
    NewClient client = null;
    Key publicKeyOfPeer = null;
    Key publicKeyOfPeers = null;
    int nonce;
    Scanner scn = new Scanner(System.in);
    Gui gui = new Gui("");

    // Constructor
    public PeerUserTwoHandler(Socket s, ObjectInputStream objectInputStream, ObjectOutputStream objectOutputStream, NewClient client)
    {
        this.s = s;
        this.objectInputStream = objectInputStream;
        this.objectOutputStream = objectOutputStream;
        this.client = client;
        gui.setName(client.getUserName());				// Set GUI Title as Client Name
        gui.setObjectOutputStream(objectOutputStream);
        gui.setObjectInputStream(objectInputStream);
        gui.setUserName(client.getUserName());
        gui.setNewClient(client);
        nonce = (int) (Math.random() * 10);
    }

    @Override
    public void run()
    {
        byte[] takenMessage = new byte[0], cipher = new byte[0];
        Object o = null;
        byte[] encryptedMessage;
        boolean encryptedNonceWaiting = false;
        boolean sendOneTime = false;
        Crypt crypt = new Crypt();
        boolean connecting = false;
        boolean chatModeOn = false;
        boolean cip = false;
        
        while (true)
        {
            try {
                o = (Object) objectInputStream.readObject();
                if(!connecting)
                {
                    if (o instanceof byte[])
                    {
//                        System.out.println("Certificate is Brought");
                        if (certificateOfnewPeer == null)
                            certificateOfnewPeer = (byte[]) o;
                        else if (publicKeyOfPeer == null) {
                            encryptedMessage = (byte[]) o;
                            publicKeyOfPeer = crypt.decrypt(certificateOfnewPeer, client.serverPublicKey);
                            System.out.println(crypt.decryptString(encryptedMessage, publicKeyOfPeers));
                            if (!Base64.getEncoder().encodeToString(publicKeyOfPeer.getEncoded()).equals(Base64.getEncoder().encodeToString(publicKeyOfPeers.getEncoded())))
                                System.out.println("Danger");
                            String commingMessage = "0";
                            commingMessage = crypt.decryptString(encryptedMessage, publicKeyOfPeers);
                            int comingNonce = Integer.parseInt(commingMessage);
                            if (comingNonce == nonce) {
                                objectOutputStream.writeObject(new String("ACK"));
                                connecting = true;
                                o = null;
                                System.out.println("Chat mode on in secure");
                                chatModeOn = true;
                            }
                        } else {
                            encryptedMessage = (byte[]) o;
                            String commingMessage = crypt.decryptString(encryptedMessage, publicKeyOfPeer);
                            System.out.println("Coming message is :" + commingMessage);
                        }
                    } 
                    else if (o instanceof Key) {
                        publicKeyOfPeers = (Key) o;
                    } 
                    else if (o instanceof String) {
                    	// System.out.println("String is brought");
                        String stringComing = (String) o;
                        System.out.println(stringComing);
                        if (stringComing.contains("username "))
                            userNameOfClient = stringComing.replace("username ", "");

                    }
                }

            } catch (Exception e){
                e.printStackTrace();
                System.out.println("Olmadı be");
            }
            try {
                if(userNameOfClient != "" && certificateOfnewPeer != null && !sendOneTime && !connecting) {
                    objectOutputStream.writeObject(new Integer(nonce));
                    gui.setNonce(nonce);
                    objectOutputStream.writeObject(client.getCertificate());
                    sendOneTime = true;
                    encryptedNonceWaiting = true;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            try{ // bağlantı kurulduysa
                if (connecting) {
                    if (o instanceof String) {
                        String stringComing = (String) o;
                        System.out.println(stringComing);
                        gui.setL1("Message mode on");
                    }
                    else if (o instanceof  byte[]) {
                        boolean ready = false;
                        if (!cip) {
                            takenMessage = (byte[]) o;
                            cip = true;
                        }
                        else {
                            cipher = (byte[]) o;
                            cip = false;
                            ready = true;
                        }
                        if (!cip && ready) {
                            crypt = new Crypt();
                            byte[] chat = crypt.cbcBlockCipherDecrypt(takenMessage, cipher, client.encryprtionKey, client.iv);
                            chat = crypt.splityTheArray(chat, client.encryprtionKey, nonce);
                            System.out.println(new String(chat));
                        }
                    }
                    
                    gui.setL1("Message mode on");
                }
            } catch (Exception e){
            	e.printStackTrace();
            }

        }
    }

}
