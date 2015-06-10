package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import java.io.File;

import org.junit.Test;

import eu.europa.esig.dss.x509.CertificateToken;

public class DSSPKUtilsTest {

	@Test
	public void getPublicKeyEncryptionAlgo() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/BA-QC-Wurzel-CA-2_PN.txt"));
		String publicKeyEncryptionAlgo = DSSPKUtils.getPublicKeyEncryptionAlgo(certificate.getPublicKey());
		assertEquals("RSA", publicKeyEncryptionAlgo);
	}

	@Test
	public void getPublicKeySize() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/BA-QC-Wurzel-CA-2_PN.txt"));
		assertEquals(2048, DSSPKUtils.getPublicKeySize(certificate.getPublicKey()));
	}

}
