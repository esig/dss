package eu.europa.esig.dss.cades.validation;

import java.util.Date;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class GetOriginalDocumentTest {

	private static String HELLO_WORLD = "HELLO WORLD !";

	@Test
	public final void getOriginalDocumentFromEnvelopingSignature() throws Exception {
		DSSDocument document = new InMemoryDocument(HELLO_WORLD.getBytes());

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CAdESService service = new CAdESService(certificateVerifier);

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<DSSDocument> results = validator.getOriginalDocuments(reports.getDiagnosticData().getFirstSignatureId());
		Assert.assertEquals(1, results.size());

		String firstDocument = new String(Utils.toByteArray(document.openStream()));
		String secondDocument = new String(Utils.toByteArray(results.get(0).openStream()));
		Assert.assertEquals(firstDocument, secondDocument);
	}

	@Test
	public final void getOriginalDocumentFromEnvelopingSignatureWithBase64EncodedContent() throws Exception {
		DSSDocument document = new InMemoryDocument(Base64.encode(HELLO_WORLD.getBytes()));

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CAdESService service = new CAdESService(certificateVerifier);

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		List<DSSDocument> results = validator.getOriginalDocuments(reports.getDiagnosticData().getFirstSignatureId());
		Assert.assertEquals(1, results.size());

		String firstDocument = new String(HELLO_WORLD.getBytes());
		String secondDocument = new String(Utils.toByteArray(results.get(0).openStream()));
		Assert.assertEquals(firstDocument, secondDocument);
	}

	@Test(expected = DSSException.class)
	public final void getOriginalDocumentFromDetachedSignature() throws Exception {
		DSSDocument document = new InMemoryDocument(HELLO_WORLD.getBytes());

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

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(signatureParameters.getSignatureAlgorithm(), privateKeyEntry, dataToSign);
		final DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		validator.getOriginalDocuments(reports.getDiagnosticData().getFirstSignatureId());
	}
}
