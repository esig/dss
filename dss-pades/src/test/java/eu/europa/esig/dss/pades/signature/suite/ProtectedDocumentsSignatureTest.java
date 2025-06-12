/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.exception.InvalidPasswordException;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProtectedDocumentsSignatureTest extends AbstractPAdESTestValidation {

	private final char[] correctProtectionPhrase = new char[]{ ' ' };
	private final char[] wrongProtectionPhrase = new char[]{ 'A', 'A', 'A', 'A'};

	private final DSSDocument openProtected = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/open_protected.pdf"), "sample.pdf", MimeTypeEnum.PDF);

	private final DSSDocument editionProtectedNone = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/edition_protected_none.pdf"), "sample.pdf", MimeTypeEnum.PDF);

	private final DSSDocument editionProtectedSigningAllowedNoField = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/edition_protected_signing_allowed_no_field.pdf"), "sample.pdf",
			MimeTypeEnum.PDF);

	private final DSSDocument editionProtectedSigningAllowedWithField = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/edition_protected_signing_allowed_with_field.pdf"), "sample.pdf",
			MimeTypeEnum.PDF);

	private final DSSDocument protectedWithEmptyFields = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/protected_two_empty_fields.pdf"), "sample.pdf",
			MimeTypeEnum.PDF);

	@Test
	void validateEmptyDocsCorrectPassword() {
		assertNotNull(validateEmptyDocWithPassword(openProtected, correctProtectionPhrase));
		assertNotNull(validateEmptyDocWithPassword(editionProtectedNone, correctProtectionPhrase));
		assertNotNull(validateEmptyDocWithPassword(editionProtectedSigningAllowedNoField, correctProtectionPhrase));
		assertNotNull(validateEmptyDocWithPassword(editionProtectedSigningAllowedWithField, correctProtectionPhrase));
	}

	@Test
	void validateEmptyDocsWrongPassword() {
		Exception exception = assertThrows(InvalidPasswordException.class,
				() -> validateEmptyDocWithPassword(openProtected, wrongProtectionPhrase));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class,
				() -> validateEmptyDocWithPassword(editionProtectedNone, wrongProtectionPhrase));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class,
				() -> validateEmptyDocWithPassword(editionProtectedSigningAllowedNoField, wrongProtectionPhrase));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class,
				() -> validateEmptyDocWithPassword(editionProtectedSigningAllowedWithField, wrongProtectionPhrase));
		assertTrue(exception.getMessage().contains("Encrypted document"));
	}

	@Test
	void validateEmptyDocsNoPassword() {
		Exception exception = assertThrows(InvalidPasswordException.class,
				() -> validateEmptyDocWithPassword(openProtected, null));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		assertNotNull(validateEmptyDocWithPassword(editionProtectedNone, null));
		assertNotNull(validateEmptyDocWithPassword(editionProtectedSigningAllowedNoField, null));
		assertNotNull(validateEmptyDocWithPassword(editionProtectedSigningAllowedWithField, null));
	}

	private Reports validateEmptyDocWithPassword(DSSDocument doc, char[] passProtection) {
		PDFDocumentValidator validator = (PDFDocumentValidator) SignedDocumentValidator.fromDocument(doc);
		validator.setPasswordProtection(passProtection);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		return validator.validateDocument();
	}

	@Test
	void signatureOperationsCorrectPassword() throws Exception {
		DSSDocument document = sign(openProtected, correctProtectionPhrase);
		verify(document);

		document = sign(editionProtectedNone, correctProtectionPhrase);
		verify(document);

		document = sign(editionProtectedSigningAllowedNoField, correctProtectionPhrase);
		verify(document);

		document = sign(editionProtectedSigningAllowedWithField, correctProtectionPhrase);
		verify(document);
	}

	@Test
	void signatureOperationsNoPassword() {

		DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service = new PAdESService(
				getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters parameters = getParameters();
		SignatureValue sigValue = new SignatureValue();
		sigValue.setAlgorithm(parameters.getSignatureAlgorithm());
		PAdESTimestampParameters timestampParameters = getTimestampParameters();

		Exception exception = assertThrows(InvalidPasswordException.class, () -> service.getContentTimestamp(openProtected, parameters));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class, () -> service.getDataToSign(openProtected, parameters));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class, () -> service.signDocument(openProtected, parameters, sigValue));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class, () -> service.timestamp(openProtected, timestampParameters));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class, () -> service.getContentTimestamp(openProtected, parameters));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class, () -> service.getDataToSign(openProtected, parameters));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class, () -> service.signDocument(openProtected, parameters,sigValue));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class, () -> service.timestamp(openProtected, timestampParameters));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		// --------
		exception = assertThrows(ProtectedDocumentException.class,
				() -> service.getContentTimestamp(editionProtectedNone, parameters));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		exception = assertThrows(ProtectedDocumentException.class,
				() -> service.getDataToSign(editionProtectedNone, parameters));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		exception = assertThrows(ProtectedDocumentException.class,
				() -> service.signDocument(editionProtectedNone, parameters, sigValue));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		exception = assertThrows(ProtectedDocumentException.class,
				() -> service.timestamp(editionProtectedNone, timestampParameters));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		// --------
		exception = assertThrows(ProtectedDocumentException.class,
				() -> service.getContentTimestamp(editionProtectedSigningAllowedNoField, parameters));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		exception = assertThrows(ProtectedDocumentException.class,
				() -> service.getDataToSign(editionProtectedSigningAllowedNoField, parameters));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		exception = assertThrows(ProtectedDocumentException.class, () -> service.signDocument(editionProtectedSigningAllowedNoField,
				parameters, sigValue));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		exception = assertThrows(ProtectedDocumentException.class,
				() -> service.timestamp(editionProtectedSigningAllowedNoField, timestampParameters));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		// --------
		exception = assertThrows(ProtectedDocumentException.class,
				() -> service.getContentTimestamp(editionProtectedSigningAllowedWithField, parameters));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		exception = assertThrows(ProtectedDocumentException.class,
				() -> service.getDataToSign(editionProtectedSigningAllowedWithField, parameters));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		exception = assertThrows(ProtectedDocumentException.class, () -> service
				.signDocument(editionProtectedSigningAllowedWithField, parameters, sigValue));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		exception = assertThrows(ProtectedDocumentException.class,
				() -> service.timestamp(editionProtectedSigningAllowedWithField, timestampParameters));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

	}
	
	@Test
	void signWithNoPassword() {
		Exception exception = assertThrows(InvalidPasswordException.class, () -> sign(openProtected, null));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedNone, null));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		exception = assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedSigningAllowedNoField, null));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());

		exception = assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedSigningAllowedWithField, null));
		assertEquals("The creation of new signatures is not permitted in the current document. " +
				"Reason : PDF Permissions dictionary does not allow modification or creation interactive form fields, " +
				"including signature fields when document is open with user-access!", exception.getMessage());
	}
	
	@Test
	void signWithWrongPassword() {
		Exception exception = assertThrows(InvalidPasswordException.class, () -> sign(openProtected, wrongProtectionPhrase));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class, () -> sign(editionProtectedNone, wrongProtectionPhrase));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class, () -> sign(editionProtectedSigningAllowedNoField, wrongProtectionPhrase));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class, () -> sign(editionProtectedSigningAllowedWithField, wrongProtectionPhrase));
		assertTrue(exception.getMessage().contains("Encrypted document"));
	}

	@Test
	void extendOperationsCorrectPasswordTest() {
		DSSDocument signedDoc = sign(openProtected, correctProtectionPhrase);

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		signatureParameters.setPasswordProtection(correctProtectionPhrase);

		DSSDocument extendedDoc = service.extendDocument(signedDoc, signatureParameters);

		Reports reports = verify(extendedDoc);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(SignatureLevel.PAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}
	
	@Test
	void extendOperationsInvalidPasswordTest() {
		Exception exception = assertThrows(InvalidPasswordException.class, () -> extend(openProtected, null));
		assertTrue(exception.getMessage().contains("Encrypted document"));

		exception = assertThrows(InvalidPasswordException.class, () -> extend(openProtected, wrongProtectionPhrase));
		assertTrue(exception.getMessage().contains("Encrypted document"));
	}
	
	@Test
	void readSignatureFieldsTest() {
		PAdESService padesService = new PAdESService(getOfflineCertificateVerifier());
		List<String> availableSignatureFields = padesService.getAvailableSignatureFields(protectedWithEmptyFields, correctProtectionPhrase);
		assertEquals(2, availableSignatureFields.size());
		assertTrue(availableSignatureFields.contains("SignatureField1"));
		assertTrue(availableSignatureFields.contains("SignatureField2"));
	}

	@Test
	void ltaSigningTest() {
		PAdESService padesService = new PAdESService(getCompleteCertificateVerifier());
		padesService.setTspSource(getGoodTsa());

		PAdESSignatureParameters signatureParameters = getParameters();
		signatureParameters.setPasswordProtection(correctProtectionPhrase);
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

		DSSDocument signed = sign(padesService, openProtected, signatureParameters);

		Reports reports = verify(signed);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.isThereALevel(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	void addSignatureFieldTest() throws Exception {
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());

		DSSDocument document = openProtected;

		List<String> signatureFields = service.getAvailableSignatureFields(document, correctProtectionPhrase);
		assertEquals(0, signatureFields.size());

		SignatureFieldParameters signatureFieldParameters = new SignatureFieldParameters();
		signatureFieldParameters.setPage(1);
		signatureFieldParameters.setOriginX(20);
		signatureFieldParameters.setOriginY(20);
		signatureFieldParameters.setWidth(150);
		signatureFieldParameters.setHeight(30);

		String firstFieldName = "SignatureField1";
		signatureFieldParameters.setFieldId(firstFieldName);
		document = service.addNewSignatureField(document, signatureFieldParameters, correctProtectionPhrase);

		signatureFields = service.getAvailableSignatureFields(document, correctProtectionPhrase);
		assertEquals(1, signatureFields.size());

		signatureFieldParameters.setOriginX(20);
		signatureFieldParameters.setOriginY(60);
		signatureFieldParameters.setWidth(150);
		signatureFieldParameters.setHeight(30);

		String secondFieldName = "SignatureField2";
		signatureFieldParameters.setFieldId(secondFieldName);

		document = service.addNewSignatureField(document, signatureFieldParameters, correctProtectionPhrase);

		signatureFields = service.getAvailableSignatureFields(document, correctProtectionPhrase);
		assertEquals(2, signatureFields.size());
		assertTrue(signatureFields.contains(firstFieldName));
		assertTrue(signatureFields.contains(secondFieldName));

		// sign
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setPasswordProtection(correctProtectionPhrase);
		signatureParameters.getImageParameters().getTextParameters().setText("My signature");
		signatureParameters.getImageParameters().getFieldParameters().setFieldId(firstFieldName);

		ToBeSigned dataToSign = service.getDataToSign(document, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		Reports reports = verify(signedDocument);
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(firstFieldName, signature.getFirstFieldName());

		signatureFields = service.getAvailableSignatureFields(signedDocument, correctProtectionPhrase);
		assertEquals(1, signatureFields.size());
		assertEquals(secondFieldName, signatureFields.get(0));
	}

	// TODO : OpenPdf does not keep the same identifier on protected documents signing
	@Test
	void recreateParamsTest() throws Exception {
		Date date = new Date();
		PAdESService padesService = new PAdESService(getCompleteCertificateVerifier());
		padesService.setTspSource(getGoodTsa());

		PAdESSignatureParameters parametersDataToBeSigned = getParameters();
		parametersDataToBeSigned.bLevel().setSigningDate(date);
		parametersDataToBeSigned.setPasswordProtection(correctProtectionPhrase);
		parametersDataToBeSigned.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

		ToBeSigned dataToSign = padesService.getDataToSign(openProtected, parametersDataToBeSigned);

		PAdESSignatureParameters parametersSignatureValue = getParameters();
		parametersSignatureValue.bLevel().setSigningDate(date);
		parametersSignatureValue.setPasswordProtection(correctProtectionPhrase);
		parametersSignatureValue.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

		SignatureValue signatureValue = getToken().sign(dataToSign, parametersSignatureValue.getDigestAlgorithm(), getPrivateKeyEntry());

		PAdESSignatureParameters parametersSign = getParameters();
		parametersSign.bLevel().setSigningDate(date);
		parametersSign.setPasswordProtection(correctProtectionPhrase);
		parametersSign.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

		DSSDocument signedDocument = padesService.signDocument(openProtected, parametersSign, signatureValue);

		PDFDocumentValidator validator = (PDFDocumentValidator) getValidator(signedDocument);
		validator.setPasswordProtection(correctProtectionPhrase);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		checkBLevelValid(diagnosticData);
		checkTimestamps(diagnosticData);
	}

	private DSSDocument sign(PAdESService service, DSSDocument doc, PAdESSignatureParameters signatureParameters) {
		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}

	private PAdESSignatureParameters getParameters() {
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		return signatureParameters;
	}

	private PAdESTimestampParameters getTimestampParameters() {
		return new PAdESTimestampParameters();
	}

	private DSSDocument sign(DSSDocument doc, char[] pwd) {

		DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service = new PAdESService(
				getOfflineCertificateVerifier());

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setPasswordProtection(pwd);

		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}
	
	private DSSDocument extend(DSSDocument doc, char[] pwd) {
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		signatureParameters.setPasswordProtection(pwd);
		
		return service.extendDocument(doc, signatureParameters);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return null;
	}

	@Override
	public void validate() {
		// do nothing
	}

	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		PDFDocumentValidator validator = (PDFDocumentValidator) super.getValidator(signedDocument);
		validator.setPasswordProtection(correctProtectionPhrase);
		return validator;
	}

}
