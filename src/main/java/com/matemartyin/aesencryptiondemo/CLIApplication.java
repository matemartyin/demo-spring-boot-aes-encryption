package com.matemartyin.aesencryptiondemo;

import com.matemartyin.aesencryptiondemo.aes.service.AESService;
import com.matemartyin.aesencryptiondemo.aes.service.dto.DecryptMessage;
import com.matemartyin.aesencryptiondemo.aes.service.dto.EncryptMessage;

import java.util.Scanner;

public class CLIApplication {

    public static void main(String[] args) throws Exception {
        if ("encrypt".equalsIgnoreCase(args[0])) {
            encrypt();
        } else if ("decrypt".equalsIgnoreCase(args[0])) {
            decrypt();
        } else {
            System.err.println("Error!");
        }
    }

    private static void decrypt() throws Exception {
        var scanner = new Scanner(System.in);

        System.out.print("Cipher text: ");
        var cipherText = scanner.nextLine();
        System.out.print("Password: ");
        var password = scanner.nextLine();

        System.out.println(AESService.decrypt(DecryptMessage.builder().cipherText(cipherText).password(password).build()));
    }

    private static void encrypt() throws Exception {
        var scanner = new Scanner(System.in);

        System.out.print("Plain text: ");
        var plainText = scanner.nextLine();
        System.out.print("Password: ");
        var password = scanner.nextLine();

        System.out.println(AESService.encrypt(EncryptMessage.builder().plainText(plainText).password(password).build()));
    }

}
