/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.signature.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.exception.InvalidPasswordException;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;
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

	private final DSSDocument protectedWithEmptyFields = new InMemoryDocument(
			getClass().getResourceAsStream("/protected/protected_two_empty_fields.pdf"), "sample.pdf",
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

		PAdESSignatureParameters parameters = getParameters();
		SignatureValue sigValue = new SignatureValue();
		PAdESTimestampParameters timestampParameters = getTimestampParameters();

		assertThrows(InvalidPasswordException.class, () -> service.getContentTimestamp(openProtected, parameters));
		assertThrows(InvalidPasswordException.class, () -> service.getDataToSign(openProtected, parameters));
		assertThrows(InvalidPasswordException.class, () -> service.signDocument(openProtected, parameters, sigValue));
		assertThrows(InvalidPasswordException.class, () -> service.timestamp(openProtected, timestampParameters));

		assertThrows(InvalidPasswordException.class,
				() -> service.getContentTimestamp(openProtected, parameters));

		assertThrows(InvalidPasswordException.class, () -> service.getDataToSign(openProtected, parameters));

		assertThrows(InvalidPasswordException.class, () -> service.signDocument(openProtected, parameters,sigValue));

		assertThrows(InvalidPasswordException.class, () -> service.timestamp(openProtected, timestampParameters));

		// --------
		assertThrows(ProtectedDocumentException.class,
				() -> service.getContentTimestamp(editionProtectedNone, parameters));

		assertThrows(ProtectedDocumentException.class,
				() -> service.getDataToSign(editionProtectedNone, parameters));

		assertThrows(ProtectedDocumentException.class,
				() -> service.signDocument(editionProtectedNone, parameters, sigValue));

		assertThrows(ProtectedDocumentException.class,
				() -> service.timestamp(editionProtectedNone, timestampParameters));

		// --------
		assertThrows(ProtectedDocumentException.class,
				() -> service.getContentTimestamp(editionProtectedSigningAllowedNoField, parameters));

		assertThrows(ProtectedDocumentException.class,
				() -> service.getDataToSign(editionProtectedSigningAllowedNoField, parameters));

		assertThrows(ProtectedDocumentException.class, () -> service.signDocument(editionProtectedSigningAllowedNoField,
				parameters, sigValue));

		assertThrows(ProtectedDocumentException.class,
				() -> service.timestamp(editionProtectedSigningAllowedNoField, timestampParameters));

		// --------
		assertThrows(ProtectedDocumentException.class,
				() -> service.getContentTimestamp(editionProtectedSigningAllowedWithField, parameters));

		assertThrows(ProtectedDocumentException.class,
				() -> service.getDataToSign(editionProtectedSigningAllowedWithField, parameters));

		assertThrows(ProtectedDocumentException.class, () -> service
				.signDocument(editionProtectedSigningAllowedWithField, parameters, sigValue));

		assertThrows(ProtectedDocumentException.class,
				() -> service.timestamp(editionProtectedSigningAllowedWithField, timestampParameters));

	}
	
	@Test
	public void signWithNoPassword() {
		assertThrows(InvalidPasswordException.class, () -> sign(openProtected, null));
		assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedNone, null));
		assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedSigningAllowedNoField, null));
		assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedSigningAllowedWithField, null));
	}
	
	@Test
	public void signWithWrongPassword() {
		assertThrows(InvalidPasswordException.class, () -> sign(openProtected, wrongProtectionPhrase));
		assertThrows(InvalidPasswordException.class, () -> sign(editionProtectedNone, wrongProtectionPhrase));
		assertThrows(InvalidPasswordException.class, () -> sign(editionProtectedSigningAllowedNoField, wrongProtectionPhrase));
		assertThrows(InvalidPasswordException.class, () -> sign(editionProtectedSigningAllowedWithField, wrongProtectionPhrase));
	}
	
	@Test
	public void extendOperationsTest() throws Exception {
		assertThrows(InvalidPasswordException.class, () -> extend(openProtected, null));
		assertThrows(InvalidPasswordException.class, () -> extend(openProtected, wrongProtectionPhrase));
	}
	
	@Test
	public void readSignatureFieldsTest() throws Exception {
		PAdESService padesService = new PAdESService(getOfflineCertificateVerifier());
		List<String> availableSignatureFields = padesService.getAvailableSignatureFields(protectedWithEmptyFields, correctProtectionPhrase);
		assertEquals(2, availableSignatureFields.size());
		assertTrue(availableSignatureFields.contains("SignatureField1"));
		assertTrue(availableSignatureFields.contains("SignatureField2"));
	}

	private PAdESSignatureParameters getParameters() {
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		return signatureParameters;
	}

	private PAdESTimestampParameters getTimestampParameters() {
		PAdESTimestampParameters params = new PAdESTimestampParameters();
		return params;
	}

	private DSSDocument sign(DSSDocument doc, String pwd) throws Exception {

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
	
	private DSSDocument extend(DSSDocument doc, String pwd) throws Exception {
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

}
