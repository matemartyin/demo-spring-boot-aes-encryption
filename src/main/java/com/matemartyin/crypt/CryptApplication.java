package com.matemartyin.crypt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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

@SpringBootApplication
@RestController
@Configuration
public class CryptApplication extends WebSecurityConfigurerAdapter {

	private static final String AES = "AES";
	public static final String PBKDF_2_WITH_HMAC_SHA_256 = "PBKDF2WithHmacSHA256";
	public static final int GCM_IV_LENGTH = 12;
	public static final int GCM_TAG_LENGTH = 16;

	private static final String salt;

	static {
		try {
			salt = generateKey(128).toString();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(CryptApplication.class, args);
	}

	@GetMapping("/encrypt")
	public String encryptText(@RequestBody EncryptRequest request) throws Exception {
		var cipherText = encrypt(request);
		return cipherText;
	}

	@GetMapping("/decrypt")
	public String decryptText(@RequestBody DecryptRequest request) throws Exception {
		var plainText = decrypt(request);
		return plainText;
	}

	public static String encrypt(EncryptRequest request) throws Exception {
		var salt = generateKey(128);
		var key = getKeyFromPassword(request.password, salt.getEncoded());
		var iv = generateIv();
		var algorithm = "AES/GCM/NoPadding";
		var cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		byte[] cipherText = cipher.doFinal(request.plainText.getBytes());
		byte[] cipherTextWithIv = ByteBuffer.allocate(iv.getIV().length + salt.getEncoded().length + cipherText.length)
				.put(iv.getIV())
				.put(salt.getEncoded())
				.put(cipherText)
				.array();

		return Base64.getEncoder().encodeToString(cipherTextWithIv);
	}

	public static String decrypt(DecryptRequest request) throws Exception{
		var bytes = Base64.getDecoder().decode(request.cipherText);
		ByteBuffer buffer = ByteBuffer.wrap(bytes);

		byte[] iv = new byte[GCM_IV_LENGTH];
		buffer.get(iv);

		byte[] salt = new byte[16];
		buffer.get(salt);

		byte[] cipherText = new byte[buffer.remaining()];
		buffer.get(cipherText);


		var key = getKeyFromPassword(request.password, salt);
		var algorithm = "AES/GCM/NoPadding";

		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));
		byte[] plainText = cipher.doFinal(cipherText);
		return new String(plainText);
	}

	public static GCMParameterSpec generateIv() {
		byte[] iv = new byte[GCM_IV_LENGTH];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		return new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
	}

	public static SecretKey getKeyFromPassword(String password, byte[] salt) throws Exception {

		var factory = SecretKeyFactory.getInstance(PBKDF_2_WITH_HMAC_SHA_256);
		var spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
		return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), AES);
	}

	public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
		var keyGenerator = KeyGenerator.getInstance(AES);
		keyGenerator.init(n);
		return keyGenerator.generateKey();
	}

	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers("/**");
	}

	public static class DecryptRequest {
		public String cipherText;
		public String password;
	}

	public static class EncryptRequest {
		public String plainText;
		public String password;
	}

}
