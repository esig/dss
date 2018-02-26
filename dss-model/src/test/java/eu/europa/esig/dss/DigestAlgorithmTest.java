package eu.europa.esig.dss;

import static org.junit.Assert.assertNotNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class DigestAlgorithmTest {

	private final DigestAlgorithm digestAlgo;

	@Parameters(name = "Digest {index} : {0}")
	public static Collection<DigestAlgorithm> data() {
		// digest algorithms which are supported by the JVM
		// other algorithms require BC,...
		return Arrays.asList(DigestAlgorithm.SHA1, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512, DigestAlgorithm.MD2,
				DigestAlgorithm.MD5);
	}

	public DigestAlgorithmTest(DigestAlgorithm digestAlgo) {
		this.digestAlgo = digestAlgo;
	}

	@Test
	public void testGetJavaName() throws NoSuchAlgorithmException {
		// DONT change digestAlgo.getJavaName() !
		MessageDigest md = MessageDigest.getInstance(digestAlgo.getJavaName());
		assertNotNull(md.digest(new byte[] { 1, 2, 3 }));
	}

}
