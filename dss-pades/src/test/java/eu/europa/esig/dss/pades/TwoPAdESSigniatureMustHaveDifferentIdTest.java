package eu.europa.esig.dss.pades;

import java.io.File;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.report.Reports;

public class TwoPAdESSigniatureMustHaveDifferentIdTest {
	
	private static final Logger logger = LoggerFactory.getLogger(TwoPAdESSigniatureMustHaveDifferentIdTest.class);

	@Test
	public void test() throws Exception {
		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/sample.pdf"));

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);
		
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.setLocation("Luxembourg");
		signatureParameters.setReason("DSS testing");
		signatureParameters.setContactInfo("Jira");
		
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		DocumentSignatureService<PAdESSignatureParameters> service = new PAdESService(certificateVerifier);
		
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		DSSDocument firstSignedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		signatureParameters.bLevel().setSigningDate(new Date());
		dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		DSSDocument secondSignedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(firstSignedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		String firstId = reports.getSimpleReport().getFirstSignatureId();
		
		
		validator = SignedDocumentValidator.fromDocument(secondSignedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		reports = validator.validateDocument();
		String secondId = reports.getSimpleReport().getFirstSignatureId();
		
		logger.info("First signature id  : " + firstId);
		logger.info("Second signature id  : " + secondId);
		
		Assert.assertNotEquals(firstId, secondId);
	}
}
