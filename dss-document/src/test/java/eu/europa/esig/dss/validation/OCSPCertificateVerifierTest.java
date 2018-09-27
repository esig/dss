package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;

public class OCSPCertificateVerifierTest {

	@Test
	public void testKeyHash() {
		CertificateToken toCheckToken = DSSUtils.loadCertificate(new File("src/test/resources/peru_client.cer"));
		CertificateToken caToken = DSSUtils.loadCertificate(new File("src/test/resources/peru_CA.cer"));
		assertTrue(toCheckToken.isSignedBy(caToken));

		OCSPSource ocspSource = new ExternalResourcesOCSPSource("/peru_ocsp.bin");
		CertificatePool validationCertPool = new CertificatePool();
		validationCertPool.getInstance(toCheckToken, CertificateSourceType.OTHER);
		validationCertPool.getInstance(caToken, CertificateSourceType.OTHER);

		OCSPCertificateVerifier ocspVerifier = new OCSPCertificateVerifier(ocspSource, validationCertPool);
		RevocationToken revocationToken = ocspVerifier.check(toCheckToken);
		assertNotNull(revocationToken);
		assertNotNull(revocationToken.getPublicKeyOfTheSigner());
	}

}
