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
package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PAdESMultipleVisibleSignaturesTest extends AbstractPAdESTestValidation {
	
	private static DSSDocument image;

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		
		image = new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG);
	}
	
	@Test
	void signatureOverlapTest() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		signatureParameters.setImageParameters(imageParameters);
		imageParameters.setImage(image);
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		documentToSign = signAndValidate();

		fieldParameters.setOriginX(150);
		fieldParameters.setOriginY(150);
		Exception exception = assertThrows(AlertException.class, () -> signAndValidate());
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
		
		fieldParameters.setOriginX(300);
		fieldParameters.setOriginY(100);
		documentToSign = signAndValidate();
		assertNotNull(documentToSign);
	}
	
	@Test
	void signatureAndTimestampOverlapTest() throws IOException {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		signatureParameters.setImageParameters(imageParameters);
		imageParameters.setImage(image);
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		documentToSign = signAndValidate();
		
		SignatureImageParameters timestampImageParameters = new SignatureImageParameters();
		SignatureFieldParameters timestampFieldParameters = new SignatureFieldParameters();
		timestampFieldParameters.setOriginX(150);
		timestampFieldParameters.setOriginY(100);
		timestampImageParameters.setFieldParameters(timestampFieldParameters);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Timestamp");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.BOTTOM);
		timestampImageParameters.setTextParameters(textParameters);
		
		PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
		timestampParameters.setImageParameters(timestampImageParameters);

		Exception exception = assertThrows(AlertException.class, () -> service.timestamp(documentToSign, timestampParameters));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
		
		timestampFieldParameters.setOriginX(300);
		documentToSign = service.timestamp(documentToSign, timestampParameters);
		
		Reports reports = verify(documentToSign);
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getSignatures().size());
		assertEquals(1, diagnosticData.getTimestampList().size());
		
		// new signature over a timestamp
		fieldParameters.setOriginX(350);
		exception = assertThrows(AlertException.class, () -> signAndValidate());
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	}
	
	@Test
	void signOverEmptySignatureFieldTest() throws IOException {
		SignatureFieldParameters signatureFieldParameters = new SignatureFieldParameters();
		signatureFieldParameters.setOriginX(100);
		signatureFieldParameters.setOriginY(100);
		signatureFieldParameters.setWidth(100);
		signatureFieldParameters.setHeight(100);
		signatureFieldParameters.setFieldId("signature1");
		
		documentToSign = service.addNewSignatureField(documentToSign, signatureFieldParameters);
		
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		signatureParameters.setImageParameters(imageParameters);
		imageParameters.setImage(image);
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		Exception exception = assertThrows(AlertException.class, () -> signAndValidate());
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
		
		signatureParameters.getImageParameters().getFieldParameters().setFieldId("signature1");
		DSSDocument signed = signAndValidate();
		assertNotNull(signed);
	}
	
	private DSSDocument signAndValidate() throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		verify(signedDocument);
		return signedDocument;
	}
	
	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		// skip (different tests)
	}

	@Override
	public void validate() {
		// do nothing
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return null;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
