package com.CSE4057;


import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.cert.Certificate;


public class NewServer {

    private static Key privateKeyOfServer=null;

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        // don't need to specify a hostname, it will be the current machine
        ServerSocket ss = new ServerSocket(8018);
        System.out.println("ServerSocket awaiting connections...");

        while (true) {
            Socket s = null;

            try {
                s = ss.accept(); // blocking call, this will wait until a connection is attempted on this port.
                System.out.println("A new client is connected : " + s.getPort());



                System.out.println("Assigning new thread for this client");
                ObjectInputStream objectInputStream=new ObjectInputStream(s.getInputStream());
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(s.getOutputStream());
                // create a new thread object
                Thread t = new ClientHandler(s,objectInputStream,objectOutputStream,getPrivateKeyOfServer());

                t.start();

            } catch (Exception e) {
                System.out.println("olmii");
            }
        }

    }
    public static Key getPrivateKeyOfServer(){return privateKeyOfServer;}
    public void generatePrivateKey(){
        //
    }
}

// ClientHandler class
class ClientHandler extends Thread
{
//    final ObjectInputStream ois;
//    final ObjectOutputStream oos;
    final Socket s;
    // create a DataInputStream so we can read data from it.
    ObjectInputStream objectInputStream = null;
    ObjectOutputStream objectOutputStream = null;
    Key publicKeyOfClient = null;
    String userNameOfClient = null;
    Key privateKeyOfServer = null;
    Certificate certificate = null;
    Boolean sendedCertificae = false;

    // Constructor
    public ClientHandler(Socket s,ObjectInputStream objectInputStream,ObjectOutputStream objectOutputStream,Key privateKeyOfServer) throws Exception {
        this.s = s;
        this.objectInputStream = objectInputStream;
        this.objectOutputStream = objectOutputStream;
        this.privateKeyOfServer = privateKeyOfServer;
    }

    @Override
    public void run()
    {
        System.out.println(objectInputStream);
        Object o=null;

        while (true){
            try {
                o = (Object) objectInputStream.readObject();
                if (o instanceof Key) {
                    System.out.println("Key is brought");
                    publicKeyOfClient = (Key) o;
                    System.out.println(publicKeyOfClient);
                } else if (o instanceof String){
                    System.out.println("String is brought");
                    String stringComing = (String) o;
                    if(stringComing.equals("verified certificate")){
                        saveCertificate(certificate);
                        sendedCertificae = true;
                    } else if(stringComing.equals("not verified certificate")){
                        sendedCertificae = false;
                    } else {
                        userNameOfClient = stringComing;
                    }
                    System.out.println(stringComing);

                }
                if(!sendedCertificae && userNameOfClient != null && publicKeyOfClient != null){
                    System.out.println("We are ready");
                    certificate = certificate(publicKeyOfClient,privateKeyOfServer);
                    objectOutputStream.writeObject(certificate);
                }

            }catch (Exception e){
                System.out.println("hata");
                return;
            }
        }


    }

    private void saveCertificate(Certificate certificate) {
//        bir yere save etmeli
    }

    public Certificate certificate(Key publicKeyOfClient, Key privateKeyOfServer){
        //kral burada imzalatırsın
        Certificate certificate=null;

        return certificate;//bize buradan sertifika dönsün
    }
}
