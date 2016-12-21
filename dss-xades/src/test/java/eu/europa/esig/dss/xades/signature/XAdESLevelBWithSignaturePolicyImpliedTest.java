package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Date;

import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.signature.AbstractTestDocumentSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESLevelBWithSignaturePolicyImpliedTest extends AbstractTestDocumentSignatureService {

	private static final Logger logger = LoggerFactory.getLogger(XAdESLevelBWithSignaturePolicyImpliedTest.class);

	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	private MockPrivateKeyEntry privateKeyEntry;

	@Before
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		Policy signaturePolicy = new Policy();

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		service = new XAdESService(certificateVerifier);

	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		String xmlContent = new String(byteArray);
		logger.info(xmlContent);
		assertTrue(xmlContent.contains(":SignaturePolicyImplied"));
		assertTrue(!xmlContent.contains(":SignaturePolicyId>"));
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.XML;
	}

	@Override
	protected boolean isBaselineT() {
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		return false;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected MockPrivateKeyEntry getPrivateKeyEntry() {
		return privateKeyEntry;
	}

}
