package eu.europa.esig.dss.spi.x509;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;

public class ListCertificateSourceTest {
	
	@Test
	public void testReflection() {
		ListCertificateSource ccv = new ListCertificateSource();
		ccv.add(new CommonTrustedCertificateSource());
		
		List<CertificateSource> sources = ccv.getSources();

		CommonCertificateSource commonCertificateSource = new CommonCertificateSource();
		assertThrows(UnsupportedOperationException.class, () -> sources.add(commonCertificateSource));
		
		assertThrows(UnsupportedOperationException.class, () -> sources.clear());
	}

}
