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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.RepeatedTest;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

@SuppressWarnings("unchecked")
class JAdESSerializationDoubleSignatureTest extends AbstractJAdESTestValidation {
	
	@RepeatedTest(10)
	@Override
	public void validate() {
		super.validate();
	}

	@Override
	protected DSSDocument getSignedDocument() {
		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.json"));

		JAdESService service = new JAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());
		
		Date time = new Date();

		JAdESSignatureParameters params = new JAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		params.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		params.setSigningCertificate(getSigningCert());
		params.bLevel().setSigningDate(time);

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		// signedDocument.save("target/" + "signedDocument.json");
		
		Calendar cal = Calendar.getInstance();
        cal.setTime(time);
        cal.add(Calendar.SECOND, 1);
        time = cal.getTime();

		params = new JAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		params.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
		params.setSigningCertificate(getSigningCert());
		params.bLevel().setSigningDate(time);

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		// doubleSignedDocument.save("target/" + "doubleSignedDocument.json");
		
		assertTrue(DSSJsonUtils.isJsonDocument(doubleSignedDocument));
		try {
			Map<String, Object> rootStructure = JsonUtil.parseJson(new String(DSSUtils.toByteArray(doubleSignedDocument)));
			
			String payload = (String) rootStructure.get(JWSConstants.PAYLOAD);
			assertNotNull(payload);
			assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(payload)));

			List<Map<String, Object>> signaturesList = (List<Map<String, Object>>) rootStructure.get(JWSConstants.SIGNATURES);
			assertTrue(Utils.isCollectionNotEmpty(signaturesList));
			assertEquals(2, signaturesList.size());
			
			for (Map<String, Object> signature : signaturesList) {
				String header = (String) signature.get(JWSConstants.PROTECTED);
				assertNotNull(header);
				assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(header)));
				
				String signatureValueBase64Url = (String) signature.get(JWSConstants.SIGNATURE);
				assertNotNull(signatureValueBase64Url);
				assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(signatureValueBase64Url)));
			}
			
		} catch (JoseException e) {
			fail("Unable to parse the signed file : " + e.getMessage());
		}
		 
		return doubleSignedDocument;
	}
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		super.checkSignatureIdentifier(diagnosticData);
		
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
			assertFalse(diagnosticData.getSignatureById(signatureId).isSignatureDuplicated());
		}

		assertNotEquals(signatureIdList.get(0), signatureIdList.get(1));
	}

	@Override
	protected void checkDigestMatchers(DiagnosticData diagnosticData) {
		super.checkDigestMatchers(diagnosticData);
		assertEquals(2, diagnosticData.getSignatures().size());
		
		SignatureWrapper signatureOne = diagnosticData.getSignatures().get(0);
		SignatureWrapper signatureTwo = diagnosticData.getSignatures().get(1);
		assertFalse(Arrays.equals(signatureOne.getDigestMatchers().get(0).getDigestValue(), signatureTwo.getDigestMatchers().get(0).getDigestValue()));
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
