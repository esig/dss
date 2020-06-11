package eu.europa.esig.dss.spi.x509.revocation.crl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;

public class ExternalResourcesCRLSourceTest {

	@Test
	public void testStreams() throws IOException {
		try (InputStream is1 = new FileInputStream("src/test/resources/crl/LTRCA.crl");
				InputStream is2 = new FileInputStream("src/test/resources/crl/LTGRCA.crl")) {
			ExternalResourcesCRLSource source = new ExternalResourcesCRLSource(is1, is2);

			assertEquals(2, source.getAllRevocationBinaries().size());
			Map<EncapsulatedRevocationTokenIdentifier, Set<RevocationOrigin>> allRevocationBinariesWithOrigins = source.getAllRevocationBinariesWithOrigins();
			assertEquals(2, allRevocationBinariesWithOrigins.size());
			for (Set<RevocationOrigin> origins : allRevocationBinariesWithOrigins.values()) {
				assertEquals(1, origins.size());
				assertEquals(RevocationOrigin.EXTERNAL, origins.iterator().next());
			}
		}
	}

	@Test
	public void testPaths() {
		ExternalResourcesCRLSource source = new ExternalResourcesCRLSource("/crl/LTRCA.crl", "/crl/LTGRCA.crl");
		assertEquals(2, source.getAllRevocationBinaries().size());
	}

	@Test
	public void noCRL() {
		DSSException exception = assertThrows(DSSException.class, () -> new ExternalResourcesCRLSource("/keystore.jks"));
		assertEquals("Unable to parse the stream (CRL is expected)", exception.getMessage());
	}

}
