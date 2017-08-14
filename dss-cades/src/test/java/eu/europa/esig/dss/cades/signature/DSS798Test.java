package eu.europa.esig.dss.cades.signature;

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
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;

public class DSS798Test {

	@Test(expected = DSSException.class)
	public void testExtendDetachedWithoutFile() throws Exception {

		DSSDocument documentToSign = new InMemoryDocument("Hello".getBytes(Charsets.UTF_8), "bin.bin");

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CAdESService service = new CAdESService(certificateVerifier);

		// Level B
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// Level T without detached document
		CertificateVerifier certificateVerifierExtend = new CommonCertificateVerifier();
		CAdESService serviceExtend = new CAdESService(certificateVerifierExtend);
		serviceExtend.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256)));

		CAdESSignatureParameters parametersExtend = new CAdESSignatureParameters();
		parametersExtend.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
		serviceExtend.extendDocument(signedDocument, parametersExtend);
	}

	@Test
	public void testExtendDetachedWithFile() throws Exception {

		DSSDocument documentToSign = new InMemoryDocument("Hello".getBytes(Charsets.UTF_8), "bin.bin");

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CAdESService service = new CAdESService(certificateVerifier);

		// Level B
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		// Level T with detached document
		CertificateVerifier certificateVerifierExtend = new CommonCertificateVerifier();
		CAdESService serviceExtend = new CAdESService(certificateVerifierExtend);
		serviceExtend.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256)));

		CAdESSignatureParameters parametersExtend = new CAdESSignatureParameters();
		parametersExtend.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
		parametersExtend.setDetachedContents(Arrays.asList(documentToSign));
		DSSDocument extendedDocument = serviceExtend.extendDocument(signedDocument, parametersExtend);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(documentToSign));
		Reports reports = validator.validateDocument();
		reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(SignatureLevel.CAdES_BASELINE_T.toString(), simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));
	}

}
