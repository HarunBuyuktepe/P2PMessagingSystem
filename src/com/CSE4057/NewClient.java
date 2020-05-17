package com.CSE4057;




import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.*;
import java.util.List;

public class NewClient {
    public static Key pub;
    public static Key pvt;
    public static String userName="";
    public static byte[] serverCertificate = null;
    public static Key serverPublicKey = null;
    public static Boolean verifyCheck = false;
    public static boolean scannerOn;
    public static int portNumber;
    public static List<Socket> socketList = null;
    public final SecretKeySpec encryprtionKey;
    public boolean wait;
    public static Mac mac = null;
    public byte[] mastersecret  = "abcdefghijklmnop".getBytes("UTF-8");  //128 bit key  symmetric key
    public byte[] initialciphertext  = "asdfgqlaslaslkalskals".getBytes("UTF-8");  //128 bit key  symmetric key
    public byte[] currentCipherText;
    public static IvParameterSpec iv ;


    public NewClient() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        //defined key pair; public and private and we generate new pair
        this.pub = kp.getPublic();
        this.pvt = kp.getPrivate();
        this.userName="";
        verifyCheck = false;
        this.serverCertificate = null;
        this.serverPublicKey = null;
        this.socketList =   new ArrayList<Socket>();
        System.out.println("Client generate its keys");
        boolean scannerOn=false;
        int portNumber = 0;
        this.wait = true;
        // Key Generation part
        generateMac();
        iv = new IvParameterSpec(mastersecret);
        encryprtionKey = new SecretKeySpec(mastersecret, "AES");
        currentCipherText = initialciphertext;
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
    public static int getPortNumber(){return portNumber;}

    public static void main(String[] args) throws Exception {
        NewClient client = new NewClient();
        System.out.println("Public Key : "+Base64.getEncoder().encodeToString(client.getPublicKey().getEncoded()));
        client.portNumber = 8035;
        ServerSocket ss ;
        Scanner scn = new Scanner(System.in);
        String name = null;

        System.out.println("Enter username : ");
        while(name == null  || name =="" ){
            name = scn.nextLine();
            client.setUserName(name);
        }
        System.out.println("Client ready to connect server ...");
        Socket socket = new Socket("localhost", 8018);
        client.socketList.add(socket);
        // create an object output stream from the output stream so we can send an object through it
        ObjectOutputStream serverObjectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream serverObjectInputStream = new ObjectInputStream(socket.getInputStream());

        System.out.println("Sending public key and username to the ServerSocket");
        serverObjectOutputStream.writeObject(client.getPublicKey());
        serverObjectOutputStream.writeObject(client.getUserName());
        serverObjectOutputStream.writeObject(client.getPortNumber());

        int portToConnect = 0;
        HashMap allPeers=null;
        HashMap portPeers=null;
        client.scannerOn=false;
        client.wait = true;
        while (true){
            Object o = serverObjectInputStream.readObject();
            if (o instanceof byte[]){
                System.out.println("Certificate come");
                client.serverCertificate = (byte[]) o;
                client.verifyCheck = true;
            } else if (o instanceof Key){
                System.out.println("Key come");
                client.serverPublicKey = (Key) o;
                client.verifyCheck = true;
            } else if (o == null){
                System.out.println("Coming object is null");
            } else if (o instanceof HashMap){
                Crypt crypt = new Crypt();
                HashMap anyhash = (HashMap) o;
                Map.Entry entry = (Map.Entry) anyhash.entrySet().iterator().next();
                if(entry.getValue() instanceof byte[]) {
                    allPeers = anyhash;
                    client.wait = true;
                } else {
                    portPeers = anyhash;
                    portPeers.forEach((key, value) -> {
                        try {
                            System.out.println("Peer : "+key + " Available Port : " + value);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    });
                    client.wait = false;
                }
            } else if (o instanceof String){
                System.out.println("Message come");
                System.out.println(o.toString());
            }
            if (client.verifyCheck && client.serverPublicKey != null && client.serverCertificate != null){
                String verify = verifySigniture(client.serverCertificate,client.serverPublicKey);
                serverObjectOutputStream.writeObject(verify);
                client.verifyCheck = false;
                client.scannerOn = true;
                client.wait = false;
            }
            if(client.scannerOn && !client.wait) {
                System.out.println("Enter your choice\n1.To get all peer certificate and username, - send all peers" +
                        "\n2.To connect user, - connect USERNAME\n3.To terminate server connection, - terminate server connection");
                String command = scn.nextLine();
                if (command.contains("terminate server connection")) {
                    socket.close();
                    break;
                } else if (command.contains("connect ")){
                    String connect="";
                    try {
                        connect = (command.replace("connect ", ""));
                    } catch (Exception e){
                        System.out.println("hata");
                    }
                    if(portPeers!=null){
                        portToConnect = (int) portPeers.get(connect);
                        for (Socket s: client.socketList) {
                            if(s.getPort() == portToConnect){
                                s.close();
                                System.out.println("Selected port closed");
                            }
                        }
                        socket.close();
                        break;
                    }
                }
                else {
                    serverObjectOutputStream.writeObject(command);
                }

            }
        }


        if(portToConnect != 0){
            System.out.println("Port to connect : "+portToConnect);
            Socket toPeerSocket = new Socket("localhost",portToConnect);
            client.socketList.add(toPeerSocket);
            ObjectOutputStream clientObjectOutputStream = new ObjectOutputStream(toPeerSocket.getOutputStream());
            ObjectInputStream clientObjectInputStream = new ObjectInputStream(toPeerSocket.getInputStream());

            clientObjectOutputStream.writeObject(new String("Hello"));
            clientObjectOutputStream.writeObject(client.serverCertificate);
            clientObjectOutputStream.writeObject(new String("username "+client.getUserName()));
            clientObjectOutputStream.writeObject(client.getPublicKey());
            Thread t = new PeerUserOneHandler(toPeerSocket,clientObjectInputStream,clientObjectOutputStream,client);

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
                    System.out.println("Olmii");
                }
            }

        }
        catch (Exception e){
            e.printStackTrace();
            System.out.println("Hata");
        }


    }

    public static String verifySigniture(byte[] serverSigniture, Key serverPublicKey) throws Exception {
        String verify = "verified certificate";
        String notVerifyed ="not verified certificate";
        Crypt crypt = new Crypt();
        Key publi = crypt.decrypt(serverSigniture,serverPublicKey);
        System.out.println("---"+Base64.getEncoder().encodeToString(publi.getEncoded()));

        if(Base64.getEncoder().encodeToString(publi.getEncoded()).equals(Base64.getEncoder().encodeToString(getPublicKey().getEncoded())))
            return verify;
        else
            return notVerifyed;

    }

    public void generateMac() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
        // generate a key from the generator
        SecretKey key = keyGen.generateKey();
        Mac mac = javax.crypto.Mac.getInstance(key.getAlgorithm());
        this.mac = mac;
    }

    public static byte[] getCertificate() {
        return serverCertificate;
    }
}
// PeerHandler class
class PeerUserOneHandler extends Thread
{
//    final ObjectInputStream ois;
//    final ObjectOutputStream oos;
    final Socket s;
    // create a DataInputStream so we can read data from it.
    ObjectInputStream objectInputStream = null;
    ObjectOutputStream objectOutputStream = null;
    Key publicKeyOfClient = null;
    String userNameOfClient = null;
    byte[] certificateOfnewPeer = null;
    int nonce = 0;
    NewClient client = null;
    boolean chatMoodOn = false;
    Scanner scn = new Scanner(System.in);
    Gui gui = new Gui("");
    // Constructor
    public PeerUserOneHandler(Socket s, ObjectInputStream objectInputStream, ObjectOutputStream objectOutputStream, NewClient client) {
        this.s = s;
        this.objectInputStream = objectInputStream;
        this.objectOutputStream = objectOutputStream;
        this.client = client;
        gui.setName(client.getUserName());
        gui.setObjectOutputStream(objectOutputStream);
        gui.setObjectInputStream(objectInputStream);
        gui.setUserName(client.getUserName());
        gui.setNewClient(client);
    }

    @Override
    public void run()
    {
        byte[] takenMessage = new byte[0],cipher = new byte[0];
        boolean cip=false;
        Object o=null;
        try {
            objectOutputStream.writeObject(new String("hello"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        Boolean cryptedNonce = false;
        while (true) {
            try { // to construct handshake
                o = (Object) objectInputStream.readObject();
                if (!chatMoodOn){
                    if (o instanceof String) {
                        String stringComing = (String) o;
                        if (stringComing.equals("ACK")) {
                            System.out.println("Connection Ok");
                            System.out.println("Chat mode on in secure\nTo send image, - **file FILE_PATH");
                            chatMoodOn = true;
                        }
//                        System.out.println(stringComing);
                        //                    gui.addToGui(stringComing);

                    } else if (o instanceof Integer) {
                        nonce = (int) o;
                        System.out.println(nonce);
                        gui.setNonce(nonce);

                    } else if (o instanceof byte[]) {
                        System.out.println("Certificate is brought");
                        certificateOfnewPeer = (byte[]) o;
                    }
                    if (certificateOfnewPeer != null && nonce != 0 && !cryptedNonce) {
                        Crypt crypt = new Crypt();
                        String toEncrypt = "" + nonce;
                        //                    System.out.println("&&&& "+Base64.getEncoder().encodeToString(client.getPrivateKey().getEncoded()));
                        byte[] cipherText = crypt.encryptText(toEncrypt, client.getPrivateKey());
                        System.out.println("text " + Base64.getEncoder().encodeToString(cipherText));
                        System.out.println(crypt.decryptString(cipherText, client.getPublicKey()));
                        objectOutputStream.writeObject(cipherText);
                        cryptedNonce = true;
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Koptu");
                return;
            }
            try{
                if(chatMoodOn){
                    if(o instanceof String){
                        String stringComing = (String) o;
                        System.out.println(stringComing);

                    }
                    else if(o instanceof  byte[]){
                        boolean ready = false;
                        if(!cip){
                            takenMessage = (byte[]) o;
                            cip = true;
                        }
                        else {
                            cipher = (byte[]) o;
                            cip = false;
                            ready = true;
                        }
                        if(!cip && ready){
                            Crypt crypt = new Crypt();
                            byte[] chat = crypt.cbcBlockCipherDecrypt(takenMessage,cipher,client.encryprtionKey,client.iv);
                            chat = crypt.splityTheArray(chat,client.encryprtionKey,nonce);
                            System.out.println(new String(chat));
                        }
                    }
                    gui.setL1("Message mode on");


                }


            } catch (Exception e) {

                System.out.println("Chat error");
            }
        }


    }

}


