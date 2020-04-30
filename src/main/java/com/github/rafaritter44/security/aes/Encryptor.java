package com.github.rafaritter44.security.aes;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Encryptor {
	
	private static final int IV_LENGTH = 16;
	
	private final String algorithm;
	private final String modeOfOperation;
	private final String padding;
	private final Random random = new SecureRandom();
	
	public Encryptor(final String algorithm, final String modeOfOperation, final String padding) {
		this.algorithm = algorithm;
		this.modeOfOperation = modeOfOperation;
		this.padding = padding;
	}
	
	public String encrypt(final String deciphered, final String key) {
		final SecretKey secretKey = new SecretKeySpec(DatatypeConverter.parseHexBinary(key), algorithm);
		final byte[] iv = new byte[IV_LENGTH];
		random.nextBytes(iv);
		try {
			final Cipher cipher = Cipher.getInstance(String.format("%s/%s/%s", algorithm, modeOfOperation, padding));
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
			final byte[] encrypted = cipher.doFinal(DatatypeConverter.parseHexBinary(deciphered));
			return DatatypeConverter.printHexBinary(concat(iv, encrypted));
		} catch(final GeneralSecurityException e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}
	
	public String decrypt(final String encrypted, final String key) {
		final SecretKey secretKey = new SecretKeySpec(DatatypeConverter.parseHexBinary(key), algorithm);
		final byte[] iv = new byte[IV_LENGTH];
		final byte[] binaryEncrypted = DatatypeConverter.parseHexBinary(encrypted);
		System.arraycopy(binaryEncrypted, 0, iv, 0, IV_LENGTH);
		try {
			final Cipher cipher = Cipher.getInstance(String.format("%s/%s/%s", algorithm, modeOfOperation, padding));
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
			final byte[] deciphered = cipher.doFinal(binaryEncrypted, IV_LENGTH, binaryEncrypted.length - IV_LENGTH);
			return DatatypeConverter.printHexBinary(deciphered);
		} catch(final GeneralSecurityException e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}
	
	private byte[] concat(final byte[] a, final byte[] b) {
		final byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}
	
}
