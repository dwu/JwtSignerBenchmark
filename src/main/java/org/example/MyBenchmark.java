package org.example;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

@Fork(1)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5)
@Measurement(iterations = 5)
@BenchmarkMode(Mode.AverageTime)
public class MyBenchmark {

	private static final String PASSWORD = "password";

	@State(Scope.Thread)
	public static class MyState {

		MyKeyProvider keyProvider;

		Algorithm algRsa256Key2048, algRsa256Key4096, algRsa256Key8192;
		Algorithm algRsa512Key2048, algRsa512Key4096, algRsa512Key8192;
		Algorithm algEcdsa256;

		@Setup(Level.Trial)
		public void doSetup() {
			try {
				keyProvider = new MyKeyProvider("keystore.jks", PASSWORD);

				algRsa256Key2048 = Algorithm.RSA256((RSAPublicKey) keyProvider.getPublicKey("test2048", PASSWORD),
						(RSAPrivateKey) keyProvider.getPrivateKey("test2048", PASSWORD));
				algRsa256Key4096 = Algorithm.RSA256((RSAPublicKey) keyProvider.getPublicKey("test4096", PASSWORD),
						(RSAPrivateKey) keyProvider.getPrivateKey("test4096", PASSWORD));
				algRsa256Key8192 = Algorithm.RSA256((RSAPublicKey) keyProvider.getPublicKey("test8192", PASSWORD),
						(RSAPrivateKey) keyProvider.getPrivateKey("test8192", PASSWORD));

				algRsa512Key2048 = Algorithm.RSA512((RSAPublicKey) keyProvider.getPublicKey("test2048", PASSWORD),
						(RSAPrivateKey) keyProvider.getPrivateKey("test2048", PASSWORD));
				algRsa512Key4096 = Algorithm.RSA512((RSAPublicKey) keyProvider.getPublicKey("test4096", PASSWORD),
						(RSAPrivateKey) keyProvider.getPrivateKey("test4096", PASSWORD));
				algRsa512Key8192 = Algorithm.RSA512((RSAPublicKey) keyProvider.getPublicKey("test8192", PASSWORD),
						(RSAPrivateKey) keyProvider.getPrivateKey("test8192", PASSWORD));

				algEcdsa256 = Algorithm.ECDSA256((ECPublicKey) keyProvider.getPublicKey("ec", PASSWORD),
						(ECPrivateKey) keyProvider.getPrivateKey("ec", PASSWORD));
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}

	// RSA

	@Benchmark
	public void buildAndSignTokenRsa256Key2048(MyState myState, Blackhole bh) {
		bh.consume(JWT.create().withIssuer("benchmark-signer").withSubject("test").sign(myState.algRsa256Key2048));
	}

	@Benchmark
	public void buildAndSignTokenRsa512Key2048(MyState myState, Blackhole bh) {
		bh.consume(JWT.create().withIssuer("benchmark-signer").withSubject("test").sign(myState.algRsa512Key2048));
	}

	@Benchmark
	public void buildAndSignTokenRsa256Key4096(MyState myState, Blackhole bh) {
		bh.consume(JWT.create().withIssuer("benchmark-signer").withSubject("test").sign(myState.algRsa256Key4096));
	}

	@Benchmark
	public void buildAndSignTokenRsa512Key4096(MyState myState, Blackhole bh) {
		bh.consume(JWT.create().withIssuer("benchmark-signer").withSubject("test").sign(myState.algRsa512Key4096));
	}

	@Benchmark
	public void buildAndSignTokenRsa256Key8192(MyState myState, Blackhole bh) {
		bh.consume(JWT.create().withIssuer("benchmark-signer").withSubject("test").sign(myState.algRsa256Key8192));
	}

	@Benchmark
	public void buildAndSignTokenRsa512Key8192(MyState myState, Blackhole bh) {
		bh.consume(JWT.create().withIssuer("benchmark-signer").withSubject("test").sign(myState.algRsa512Key8192));
	}

	// EC

	@Benchmark
	public void buildAndSignTokenEcdsa256(MyState myState, Blackhole bh) {
		bh.consume(JWT.create().withIssuer("benchmark-signer").withSubject("test").sign(myState.algEcdsa256));
	}

}
