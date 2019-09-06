package eu.europa.esig.dss.model.x509;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

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

	@Test
	public void testWithNullValue() {
		assertThrows(NullPointerException.class, () -> {
			new EncapsulatedCertificateTokenIdentifier(null);
		});
	}

}
