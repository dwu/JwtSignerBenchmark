package org.example;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

public class MyKeyProvider {
	
	private KeyStore keyStore;
	
	public MyKeyProvider(String keyStoreFile, String keyStorePassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		FileInputStream is = new FileInputStream(keyStoreFile);
        keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(is, keyStorePassword.toCharArray());
	}
	
	public PrivateKey getPrivateKey(String alias, String password) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
		return entry.getPrivateKey();
	}

	public PublicKey getPublicKey(String alias, String password) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
		return entry.getCertificate().getPublicKey();
	}
	
}
