package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class SignatureAlgorithmTest {

	private final SignatureAlgorithm signatureAlgo;

	@Parameters(name = "SignatureAlgorithm {index} : {0}")
	public static Collection<SignatureAlgorithm> data() {
		return Arrays.asList(SignatureAlgorithm.values());
	}

	public SignatureAlgorithmTest(SignatureAlgorithm signatureAlgo) {
		this.signatureAlgo = signatureAlgo;
	}

	@Test
	public void test() {
		SignatureAlgorithm retrieved = SignatureAlgorithm.getAlgorithm(signatureAlgo.getEncryptionAlgorithm(), signatureAlgo.getDigestAlgorithm(),
				signatureAlgo.getMaskGenerationFunction());
		assertEquals(signatureAlgo, retrieved);
	}

}
