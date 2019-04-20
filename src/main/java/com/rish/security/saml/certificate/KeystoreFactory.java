package com.rish.security.saml.certificate;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StreamUtils;

public class KeystoreFactory {

	private ResourceLoader resourceLoader;

	public KeystoreFactory() {
		resourceLoader = new DefaultResourceLoader();
	}

	public KeystoreFactory(ResourceLoader resourceLoader) {
		this.resourceLoader = resourceLoader;
	}

	public KeyStore loadKeystore(String certResourceLocation, String privateKeyResourceLocation, String alias,
			String keyPassword) throws Exception {
		KeyStore keystore = createEmptyKeystore();
		X509Certificate cert = loadCert(certResourceLocation);
		RSAPrivateKey privateKey = loadPrivateKey(privateKeyResourceLocation);
		addKeyToKeystore(keystore, cert, privateKey, alias, keyPassword);
		return keystore;
	}

	public void addKeyToKeystore(KeyStore keyStore, X509Certificate cert, RSAPrivateKey privateKey, String alias,
			String password) throws KeyStoreException {
		KeyStore.PasswordProtection pass = new KeyStore.PasswordProtection(password.toCharArray());
		Certificate[] certificateChain = { cert };
		keyStore.setEntry(alias, new KeyStore.PrivateKeyEntry(privateKey, certificateChain), pass);
	}

	public KeyStore createEmptyKeystore()
			throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, "".toCharArray());
		return keyStore;
	}

	public X509Certificate loadCert(String certLocation) throws CertificateException, IOException {
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		Resource certRes = resourceLoader.getResource(certLocation);
		X509Certificate cert = (X509Certificate) cf.generateCertificate(certRes.getInputStream());
		return cert;
	}

	public RSAPrivateKey loadPrivateKey(String privateKeyLocation) throws Exception {
		Resource keyRes = resourceLoader.getResource(privateKeyLocation);
		byte[] keyBytes = StreamUtils.copyToByteArray(keyRes.getInputStream());
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
		return privateKey;
	}

	public void setResourceLoader(DefaultResourceLoader resourceLoader) {
		this.resourceLoader = resourceLoader;
	}
}
