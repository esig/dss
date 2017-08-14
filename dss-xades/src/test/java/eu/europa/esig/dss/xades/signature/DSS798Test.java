package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Date;

import org.junit.Test;

import com.google.common.base.Charsets;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class DSS798Test {

	@Test(expected = DSSException.class)
	public void testExtendDetachedWithoutFile() throws Exception {

		DSSDocument documentToSign = new InMemoryDocument("Hello".getBytes(Charsets.UTF_8), "bin.bin");

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(certificateVerifier);

		// Level B
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// Level T without detached document
		CertificateVerifier certificateVerifierExtend = new CommonCertificateVerifier();
		XAdESService serviceExtend = new XAdESService(certificateVerifierExtend);
		serviceExtend.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256)));

		XAdESSignatureParameters parametersExtend = new XAdESSignatureParameters();
		parametersExtend.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		serviceExtend.extendDocument(signedDocument, parametersExtend);
	}

	@Test
	public void testExtendDetachedWithFile() throws Exception {

		DSSDocument documentToSign = new InMemoryDocument("Hello".getBytes(Charsets.UTF_8), "bin.bin");

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		XAdESService service = new XAdESService(certificateVerifier);

		// Level B
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// Level T with detached document
		CertificateVerifier certificateVerifierExtend = new CommonCertificateVerifier();
		XAdESService serviceExtend = new XAdESService(certificateVerifierExtend);
		serviceExtend.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256)));

		XAdESSignatureParameters parametersExtend = new XAdESSignatureParameters();
		parametersExtend.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		parametersExtend.setDetachedContents(Arrays.asList(documentToSign));
		DSSDocument extendedDocument = serviceExtend.extendDocument(signedDocument, parametersExtend);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(documentToSign));
		Reports reports = validator.validateDocument();
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureLevel.XAdES_BASELINE_T.toString(), simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));
	}

}
