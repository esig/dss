package eu.europa.esig.dss.xades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

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
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

public class XAdESWithTrustedOCSPResponderTest extends AbstractXAdESTestSignature {
	
	protected static final String OCSP_SKIP_USER_OCSP_RESPONDER = "ocsp-skip-ocsp-responder";

	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {		
		documentToSign = new FileDocument("src/test/resources/sample.xml");

		CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(getCertificate(OCSP_SKIP_USER_OCSP_RESPONDER));
		completeCertificateVerifier.addTrustedCertSources(trustedCertificateSource);
		service = new XAdESService(completeCertificateVerifier);
		service.setTspSource(getSelfSignedTsa());
		
		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		super.checkSigningCertificateValue(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		CertificateWrapper signingCertificate = signature.getSigningCertificate();
		assertNotNull(signingCertificate);
		
		assertTrue(Utils.isCollectionNotEmpty(signingCertificate.getOCSPAccessUrls()));
		assertTrue(Utils.isCollectionEmpty(signingCertificate.getCRLDistributionPoints()));
		
		List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
		assertEquals(1, certificateRevocationData.size());
		
		RevocationWrapper revocationWrapper = certificateRevocationData.get(0);
		assertEquals(RevocationType.OCSP, revocationWrapper.getRevocationType());
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
		return OCSP_SKIP_USER;
	}
	
}