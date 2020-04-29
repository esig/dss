package eu.europa.esig.dss.spi.x509;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

public class ListCertificateSourceTest {
	
	@Test
	public void testReflection() {
		ListCertificateSource ccv = new ListCertificateSource();
		ccv.add(new CommonTrustedCertificateSource());
		assertThrows(UnsupportedOperationException.class, () -> {
			ccv.getSources().add(new CommonCertificateSource());
		});
		
		assertThrows(UnsupportedOperationException.class, () -> {
			ccv.getSources().clear();
		});
	}

}
