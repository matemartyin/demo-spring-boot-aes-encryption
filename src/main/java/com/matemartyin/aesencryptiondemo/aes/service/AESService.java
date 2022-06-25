package com.matemartyin.aesencryptiondemo.aes.service;

import com.matemartyin.aesencryptiondemo.aes.service.dto.DecryptMessage;
import com.matemartyin.aesencryptiondemo.aes.service.dto.EncryptMessage;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
public class AESService {

    private static final String AES = "AES";
    private static final String PBKDF_2_WITH_HMAC_SHA_256 = "PBKDF2WithHmacSHA256";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int SALT_LENGTH = 16;
    private static final int SALT_LENGTH_BITS = 128;
    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";

    public static String encrypt(EncryptMessage message) throws Exception {
        var salt = generateSalt(SALT_LENGTH_BITS);
        var key = getKeyFromPassword(message.password, salt.getEncoded());
        var iv = generateIv();

        var cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        var cipherText = cipher.doFinal(message.plainText.getBytes());

        var cipherTextWithIvSalt =
                ByteBuffer.allocate(iv.getIV().length + salt.getEncoded().length + cipherText.length)
                        .put(iv.getIV())
                        .put(salt.getEncoded())
                        .put(cipherText)
                        .array();

        return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);
    }

    public static String decrypt(DecryptMessage message) throws Exception{
        var cipherTextBytes = Base64.getDecoder().decode(message.cipherText);
        var buffer = ByteBuffer.wrap(cipherTextBytes);

        var iv = getBytes(buffer, GCM_IV_LENGTH);
        var salt = getBytes(buffer, SALT_LENGTH);
        var cipherText = getBytes(buffer, buffer.remaining());

        var key = getKeyFromPassword(message.password, salt);
        var cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        var plainText = cipher.doFinal(cipherText);
        return new String(plainText);
    }

    private static byte[] getBytes(ByteBuffer buffer, int length) {
        var bytes = new byte[length];
        buffer.get(bytes);
        return bytes;
    }

    private static GCMParameterSpec generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return new GCMParameterSpec(GCM_TAG_LENGTH, iv);
    }

    private static SecretKey getKeyFromPassword(String password, byte[] salt) throws Exception {
        var factory = SecretKeyFactory.getInstance(PBKDF_2_WITH_HMAC_SHA_256);
        var spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), AES);
    }

    private static SecretKey generateSalt(int n) throws NoSuchAlgorithmException {
        var keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

}
