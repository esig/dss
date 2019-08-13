package eu.europa.esig.dss.model.x509;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public class EncapsulatedTokenIdentifierTest {

	@Test
	public void testEncapsulatedCertificateTokenIdentifier() {
		byte[] binaries = new byte[] { 1, 2, 3 };
		EncapsulatedCertificateTokenIdentifier encapsulatedTokenIdentifier = new EncapsulatedCertificateTokenIdentifier(binaries);
		assertArrayEquals(binaries, encapsulatedTokenIdentifier.getBinaries());
		byte[] digestValue = encapsulatedTokenIdentifier.getDigestValue(DigestAlgorithm.SHA256);
		assertArrayEquals(digestValue, encapsulatedTokenIdentifier.getDigestValue(DigestAlgorithm.SHA256));
		assertTrue(encapsulatedTokenIdentifier.asXmlId().startsWith("C-"));
	}

	@Test(expected = NullPointerException.class)
	public void testWithNullValue() {
		new EncapsulatedCertificateTokenIdentifier(null);
	}

}
