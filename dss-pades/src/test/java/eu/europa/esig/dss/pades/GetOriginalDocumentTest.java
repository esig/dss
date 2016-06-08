package eu.europa.esig.dss.pades;

import java.io.InputStream;
import java.util.Date;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.util.PDFTextStripper;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class GetOriginalDocumentTest {

	@Test
	public final void getOriginalDocumentFromEnvelopedSignature() throws Exception {
		DSSDocument document = new FileDocument("src/test/resources/sample.pdf");

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		PAdESService service = new PAdESService(certificateVerifier);

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		DSSDocument removeResult = validator.getOriginalDocument(reports.getDiagnosticData().getFirstSignatureId());

		InputStream is = document.openStream();
		PDDocument pdf = PDDocument.load(is, true);
		PDFTextStripper stripper = new PDFTextStripper();
		String firstDocument = stripper.getText(pdf);

		is = removeResult.openStream();
		pdf = PDDocument.load(is, true);
		String secondDocument = stripper.getText(pdf);

		// removeResult.save("C:\\Users\\axel.abinet\\Desktop\\test.pdf");
		Assert.assertEquals(firstDocument, secondDocument);
	}

	@Test
	public final void getOriginalDocumentFromEnvelopingSignature() throws Exception {
		DSSDocument document = new FileDocument("src/test/resources/sample.pdf");

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		PAdESService service = new PAdESService(certificateVerifier);

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		DSSDocument removeResult = validator.getOriginalDocument(reports.getDiagnosticData().getFirstSignatureId());
		InputStream is = document.openStream();
		PDDocument pdf = PDDocument.load(is, true);
		PDFTextStripper stripper = new PDFTextStripper();
		String firstDocument = stripper.getText(pdf);

		is = removeResult.openStream();
		pdf = PDDocument.load(is, true);
		String secondDocument = stripper.getText(pdf);

		Assert.assertEquals(firstDocument, secondDocument);
	}
}
