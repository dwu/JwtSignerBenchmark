package org.example;

import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class Main {

	public void run() throws Exception {
		// Dump supported elliptic curves

		System.out.println("Supported elliptic curves: " + Security.getProviders("AlgorithmParameters.EC")[0]
				.getService("AlgorithmParameters", "EC").getAttribute("SupportedCurves"));

		MyKeyProvider mkp = new MyKeyProvider("keystore.jks", "password");

		RSAPublicKey rsaPublicKey = (RSAPublicKey) mkp.getPublicKey("test2048", "password");
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) mkp.getPrivateKey("test2048", "password");

		Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, rsaPrivateKey);
		String token = JWT.create().withIssuer("benchmark-signer").withSubject("test").sign(algorithm);
		System.out.println("RSA signed: " + token);

		ECPublicKey ecPublicKey = (ECPublicKey) mkp.getPublicKey("ec", "password");
		ECPrivateKey ecPrivateKey = (ECPrivateKey) mkp.getPrivateKey("ec", "password");

		algorithm = Algorithm.ECDSA256(ecPublicKey, ecPrivateKey);
		token = JWT.create().withIssuer("benchmark-signer").withSubject("test").sign(algorithm);
		System.out.println("EC signed: " + token);
	}

	public static void main(String[] args) {
		try {
			Main m = new Main();
			m.run();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
