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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESDoubleSignatureWithNonB64Test extends AbstractJAdESTestValidation {
	
	private static final String ORIGINAL_STRING = "Hello World!";
	
	private DSSDocument toBeSigned;
	private JAdESService service;
	
	@BeforeEach
	void init() {
		toBeSigned = new InMemoryDocument(ORIGINAL_STRING.getBytes());
		
		service = new JAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@Override
	protected DSSDocument getSignedDocument() {
		DSSDocument signedDocument = getCompleteSerializationSignature(toBeSigned);
		// signedDocument.save("target/" + "signedDocument.json");

		awaitOneSecond();

		DSSDocument doubleSignedDocument = getCompleteSerializationSignature(signedDocument);
		// doubleSignedDocument.save("target/" + "doubleSignedDocument.json");
		
		assertTrue(DSSJsonUtils.isJsonDocument(doubleSignedDocument));
		
		assertTrue(new String(DSSUtils.toByteArray(doubleSignedDocument)).contains(ORIGINAL_STRING));
		 
		return doubleSignedDocument;
	}
	
	private DSSDocument getCompleteSerializationSignature(DSSDocument documentToSign) {
		JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setBase64UrlEncodedPayload(false);
		
		return sign(documentToSign, signatureParameters);
	}
	
	private DSSDocument sign(DSSDocument documentToSign, JAdESSignatureParameters signatureParameters) {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentToSign, signatureParameters, signatureValue);
	}
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		super.checkSignatureIdentifier(diagnosticData);

		assertEquals(2, diagnosticData.getSignatureIdList().size());
	}

	@Override
	protected void checkDigestMatchers(DiagnosticData diagnosticData) {
		super.checkDigestMatchers(diagnosticData);
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		SignatureWrapper signatureOne = signatures.get(0);
		SignatureWrapper signatureTwo = signatures.get(1);
		
		assertEquals(signatureOne.getDigestMatchers().size(), signatureTwo.getDigestMatchers().size());
		assertFalse(Arrays.equals(signatureOne.getDigestMatchers().get(0).getDigestValue(), signatureTwo.getDigestMatchers().get(0).getDigestValue()));
	}
	
	@Test
	void signWithDifferentB64Test() {
		DSSDocument signedDocument = getCompleteSerializationSignature(toBeSigned);
		
		JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		signatureParameters.setSigningCertificate(getSigningCert());
		
		Exception exception = assertThrows(IllegalArgumentException.class, () -> sign(signedDocument, signatureParameters));
		assertEquals("'b64' value shall be the same for all signatures! "
				+ "Change 'Base64UrlEncodedPayload' signature parameter or sign another file!", exception.getMessage());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
