package com.CSE4057;

public class Main {

    public static void main(String[] args) {
        System.out.println("Allah yardımcımız olsun, kasıcı bir proje");
        /*
        * Server class: gelen her request için bir socket bağlantısı açıyor, ve bu bağlantı sürekli açık kalıyor
        *               ancak biz kapatana kadar
        *
        * Client 1 ve 2 class: request gönderen ve socket bağlantısı açan clientlarımız
        * (Info. Client 1 = Client2)
        *
        * sonraki aşamalarımız
        *
        * 1. Public Key - private key çiftini clint'a oluşturup server'a gönderip ardından
        *  Server bu anahtarı imzalatıp ve bir sertifika oluşturmak, sertifikayı depolayıp (database yada geçici txt dosyasında yada hash map)
        *   kullanıcıya bir kopyasını göndermek.
        *
        * 2. Kullanıcı sertifikayı aldığında sertifikanın doğru olduğunu ve
        *           ortak anahtarın sunucu tarafından doğru bir şekilde alındığını doğrulaması
        *
        * bu iki madde bitince Public Key Certification kısmı bitiyor hacı, önemli olan parçalaya parçalaya gitmek
        * parçadan gidersek boğuluruz
        *
        *
        * */
    }
}
