package eu.europa.esig.dss.pades.signature.suite;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.EncryptedDocumentException;
import eu.europa.esig.dss.pades.InvalidPasswordException;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ProtectedDocumentsSignatureTest extends PKIFactoryAccess {

	private final String correctProtectionPhrase = " ";
	private final String wrongProtectionPhrase = "AAAA";

	private final DSSDocument openProtected = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/open_protected.pdf"), "sample.pdf", MimeType.PDF);

	private final DSSDocument editionProtectedNone = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/edition_protected_none.pdf"), "sample.pdf", MimeType.PDF);

	private final DSSDocument editionProtectedSigningAllowedNoField = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/edition_protected_signing_allowed_no_field.pdf"), "sample.pdf",
			MimeType.PDF);

	private final DSSDocument editionProtectedSigningAllowedWithField = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/edition_protected_signing_allowed_with_field.pdf"), "sample.pdf",
			MimeType.PDF);

	@Test
	public void validateEmptyDocsCorrectPassword() {
		assertNotNull(validateEmptyDocWithPassword(openProtected, correctProtectionPhrase));
		assertNotNull(validateEmptyDocWithPassword(editionProtectedNone, correctProtectionPhrase));
		assertNotNull(validateEmptyDocWithPassword(editionProtectedSigningAllowedNoField, correctProtectionPhrase));
		assertNotNull(validateEmptyDocWithPassword(editionProtectedSigningAllowedWithField, correctProtectionPhrase));
	}

	@Test
	public void validateEmptyDocsWrongPassword() {
		assertThrows(InvalidPasswordException.class,
				() -> validateEmptyDocWithPassword(openProtected, wrongProtectionPhrase));
		assertThrows(InvalidPasswordException.class,
				() -> validateEmptyDocWithPassword(editionProtectedNone, wrongProtectionPhrase));
		assertThrows(InvalidPasswordException.class,
				() -> validateEmptyDocWithPassword(editionProtectedSigningAllowedNoField, wrongProtectionPhrase));
		assertThrows(InvalidPasswordException.class,
				() -> validateEmptyDocWithPassword(editionProtectedSigningAllowedWithField, wrongProtectionPhrase));
	}

	@Test
	public void validateEmptyDocsNoPassword() {
		assertThrows(InvalidPasswordException.class, () -> validateEmptyDocWithPassword(openProtected, null));
		assertNotNull(validateEmptyDocWithPassword(editionProtectedNone, null));
		assertNotNull(validateEmptyDocWithPassword(editionProtectedSigningAllowedNoField, null));
		assertNotNull(validateEmptyDocWithPassword(editionProtectedSigningAllowedWithField, null));
	}

	private Reports validateEmptyDocWithPassword(DSSDocument doc, String passProtection) {
		PDFDocumentValidator validator = (PDFDocumentValidator) SignedDocumentValidator.fromDocument(doc);
		validator.setPasswordProtection(passProtection);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		return validator.validateDocument();
	}

	@Test
	public void signatureOperationsNoPassword() {

		DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service = new PAdESService(
				getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		assertThrows(EncryptedDocumentException.class,
				() -> service.getContentTimestamp(openProtected, getParameter()));

		assertThrows(EncryptedDocumentException.class, () -> service.getDataToSign(openProtected, getParameter()));

		assertThrows(EncryptedDocumentException.class,
				() -> service.signDocument(openProtected, getParameter(), new SignatureValue()));

		assertThrows(EncryptedDocumentException.class, () -> service.timestamp(openProtected, getTimestampParameter()));

		// --------
		assertThrows(EncryptedDocumentException.class,
				() -> service.getContentTimestamp(editionProtectedNone, getParameter()));

		assertThrows(EncryptedDocumentException.class,
				() -> service.getDataToSign(editionProtectedNone, getParameter()));

		assertThrows(EncryptedDocumentException.class,
				() -> service.signDocument(editionProtectedNone, getParameter(), new SignatureValue()));

		assertThrows(EncryptedDocumentException.class,
				() -> service.timestamp(editionProtectedNone, getTimestampParameter()));

		// --------
		assertThrows(EncryptedDocumentException.class,
				() -> service.getContentTimestamp(editionProtectedSigningAllowedNoField, getParameter()));

		assertThrows(EncryptedDocumentException.class,
				() -> service.getDataToSign(editionProtectedSigningAllowedNoField, getParameter()));

		assertThrows(EncryptedDocumentException.class, () -> service.signDocument(editionProtectedSigningAllowedNoField,
				getParameter(), new SignatureValue()));

		assertThrows(EncryptedDocumentException.class,
				() -> service.timestamp(editionProtectedSigningAllowedNoField, getTimestampParameter()));

		// --------
		assertThrows(EncryptedDocumentException.class,
				() -> service.getContentTimestamp(editionProtectedSigningAllowedWithField, getParameter()));

		assertThrows(EncryptedDocumentException.class,
				() -> service.getDataToSign(editionProtectedSigningAllowedWithField, getParameter()));

		assertThrows(EncryptedDocumentException.class, () -> service
				.signDocument(editionProtectedSigningAllowedWithField, getParameter(), new SignatureValue()));

		assertThrows(EncryptedDocumentException.class,
				() -> service.timestamp(editionProtectedSigningAllowedWithField, getTimestampParameter()));

	}

	@Test
	public void signatureOperationsCorrectPassword() {

//		DSSDocument document = null;
//
//		document = sign(openProtected, correctProtectionPhrase);
//		validate(document, correctProtectionPhrase);
//
//		document = sign(editionProtectedNone, correctProtectionPhrase);
//		validate(document, correctProtectionPhrase);
//
//		document = sign(editionProtectedSigningAllowedNoField, correctProtectionPhrase);
//		validate(document, correctProtectionPhrase);
//
//		document = sign(editionProtectedSigningAllowedWithField, correctProtectionPhrase);
//		validate(document, correctProtectionPhrase);

		assertThrows(EncryptedDocumentException.class, () -> sign(openProtected));
		assertThrows(EncryptedDocumentException.class, () -> sign(editionProtectedNone));
		assertThrows(EncryptedDocumentException.class, () -> sign(editionProtectedSigningAllowedNoField));
		assertThrows(EncryptedDocumentException.class, () -> sign(editionProtectedSigningAllowedWithField));

	}

	private PAdESSignatureParameters getParameter() {
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		return signatureParameters;
	}

	private PAdESTimestampParameters getTimestampParameter() {
		PAdESTimestampParameters params = new PAdESTimestampParameters();
		return params;
	}

	private DSSDocument sign(DSSDocument doc) {

		DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service = new PAdESService(
				getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}

//	private void validate(DSSDocument doc, String pwd) {
//
//		PDFDocumentValidator validator = (PDFDocumentValidator) SignedDocumentValidator.fromDocument(doc);
//		validator.setCertificateVerifier(getOfflineCertificateVerifier());
//		validator.setPasswordProtection(pwd);
//
//		Reports reports = validator.validateDocument();
//		assertNotNull(reports);
//
//		DiagnosticData diagnosticData = reports.getDiagnosticData();
//		assertEquals(1, diagnosticData.getSignatures().size());
//
//		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
//		assertTrue(signatureWrapper.isSignatureValid());
//
//	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
