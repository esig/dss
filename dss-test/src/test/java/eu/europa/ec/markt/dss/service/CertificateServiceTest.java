package eu.europa.ec.markt.dss.service;

import static org.junit.Assert.assertNotNull;

import java.security.SignatureException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.tsp.TSPUtil;
import org.junit.Test;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

public class CertificateServiceTest {

	private CertificateService service = new CertificateService();

	@Test
	public void isSelfSigned() throws Exception {
		DSSPrivateKeyEntry entry = service.generateSelfSignedCertificate(SignatureAlgorithm.RSA_SHA256);

		CertificateToken certificate = entry.getCertificate();
		certificate.isSignedBy(certificate);
	}

	@Test(expected = SignatureException.class)
	public void isChildCertificateNotSelfSigned() throws Exception {
		DSSPrivateKeyEntry entryChain = service.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		// Child certificate is signed with the issuer's private key
		CertificateToken childCertificate = entryChain.getCertificate();
		childCertificate.isSignedBy(childCertificate);
	}

	@Test
	public void generateTspCertificate() throws Exception {
		DSSPrivateKeyEntry keyEntry = service.generateTspCertificate(SignatureAlgorithm.RSA_SHA256);
		assertNotNull(keyEntry);
		CertificateToken certificate = keyEntry.getCertificate();
		TSPUtil.validateCertificate(new X509CertificateHolder(certificate.getEncoded()));
	}
}