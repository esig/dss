package eu.europa.esig.dss.xades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

// see DSS-2140
public class XAdESWithNotAcceptableOCSPTest extends AbstractXAdESTestSignature {

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	private String signingAlias;

	@BeforeEach
	public void init() throws Exception {		
		documentToSign = new FileDocument("src/test/resources/sample.xml");

		service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getSelfSignedTsa());
	}
	
	private void initSignatureParameters() {
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
	}
	
	@Override
	@Test
	public void signAndVerify() {
		signingAlias = OCSP_SKIP_USER_WITH_CRL;
		initSignatureParameters();
		
		super.signAndVerify();
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		super.checkSigningCertificateValue(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		
		assertTrue(Utils.isCollectionNotEmpty(signingCertificate.getOCSPAccessUrls()));
		assertTrue(Utils.isCollectionNotEmpty(signingCertificate.getCRLDistributionPoints()));
		
		List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());
		
		RevocationWrapper revocationWrapper = certificateRevocationData.get(0);
		// OCSP is skipped
		assertEquals(RevocationType.CRL, revocationWrapper.getRevocationType());
	}
	
	@Test
	public void ocspOnlyTest() {
		signingAlias = OCSP_SKIP_USER;
		initSignatureParameters();
		
		// no alternative CRL distribution point
		Exception exception = assertThrows(Exception.class, () -> sign());
		assertTrue(exception.getMessage().contains("Revocation data is missing for one or more certificate(s)."));
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}
	
}