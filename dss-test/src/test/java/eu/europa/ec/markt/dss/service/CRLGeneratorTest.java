package eu.europa.ec.markt.dss.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Date;

import org.bouncycastle.asn1.x509.CRLReason;
import org.junit.Test;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;

public class CRLGeneratorTest {

	private CertificateService certificateService = new CertificateService();
	private CRLGenerator crlGenerator = new CRLGenerator();

	@Test
	public void test() throws Exception {
		DSSPrivateKeyEntry issuerKeyEntry = certificateService.generateSelfSignedCertificate(SignatureAlgorithm.RSA_SHA256);
		DSSPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256, issuerKeyEntry);
		X509CRL generatedCRL = crlGenerator.generateCRL(privateKeyEntry.getCertificate().getCertificate(), issuerKeyEntry, new Date(), CRLReason.privilegeWithdrawn);
		assertNotNull(generatedCRL);

		assertEquals(issuerKeyEntry.getCertificate().getSubjectX500Principal(), generatedCRL.getIssuerX500Principal());

		X509CRLEntry revokedCertificate = generatedCRL.getRevokedCertificate(privateKeyEntry.getCertificate().getSerialNumber());
		assertNotNull(revokedCertificate);
	}

}
