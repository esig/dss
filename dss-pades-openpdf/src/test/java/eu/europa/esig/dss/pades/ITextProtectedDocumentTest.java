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
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ITextProtectedDocumentTest extends AbstractPAdESTestValidation {
	
	private final String correctProtectionPhrase = " ";

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
	
	@Test
	public void signatureOperationsCorrectPassword() {
		assertThrows(ProtectedDocumentException.class, () -> sign(openProtected, correctProtectionPhrase));
		assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedNone, correctProtectionPhrase));
		assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedSigningAllowedNoField, correctProtectionPhrase));
		assertThrows(ProtectedDocumentException.class, () -> sign(editionProtectedSigningAllowedWithField, correctProtectionPhrase));
	}
	
	@Test
	public void timestampTest() {
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
		timestampParameters.setPasswordProtection(correctProtectionPhrase);

		assertThrows(ProtectedDocumentException.class, () -> service.timestamp(openProtected, timestampParameters));
		assertThrows(ProtectedDocumentException.class, () -> service.timestamp(editionProtectedNone, timestampParameters));
		assertThrows(ProtectedDocumentException.class, () -> service.timestamp(editionProtectedSigningAllowedNoField, timestampParameters));
		assertThrows(ProtectedDocumentException.class, () -> service.timestamp(editionProtectedSigningAllowedWithField, timestampParameters));
	}
	
	@Test
	public void addSignatureFieldTest() {
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		
		DSSDocument document = openProtected;
		
		List<String> signatureFields = service.getAvailableSignatureFields(document, correctProtectionPhrase);
		assertEquals(0, signatureFields.size());
		
		SignatureFieldParameters signatureFieldParameters = new SignatureFieldParameters();
		signatureFieldParameters.setPage(0);
		signatureFieldParameters.setFieldId("SignatureField1");
		assertThrows(ProtectedDocumentException.class, () -> service.addNewSignatureField(document, signatureFieldParameters, correctProtectionPhrase));
	}

	private DSSDocument sign(DSSDocument doc, String pwd) {

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

}
