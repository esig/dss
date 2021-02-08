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
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class JAdESLevelTFlattenedSerializationTest extends AbstractJAdESTestSignature {

	private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private DSSDocument documentToSign;
	private JAdESSignatureParameters signatureParameters;

	@BeforeEach
	public void init() throws Exception {
		service = new JAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_T);
		
		signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
	}
	
	@Override
	@SuppressWarnings("unchecked")
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		
		assertTrue(DSSJsonUtils.isJsonDocument(new InMemoryDocument(byteArray)));
		try {
			Map<String, Object> rootStructure = JsonUtil.parseJson(new String(byteArray));
			
			String firstEntryName = rootStructure.keySet().iterator().next();
			assertEquals(JWSConstants.PAYLOAD, firstEntryName);
			
			String payload = (String) rootStructure.get(firstEntryName);
			assertNotNull(payload);
			assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(payload)));
			
			String header = (String) rootStructure.get(JWSConstants.PROTECTED);
			assertNotNull(header);
			assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(header)));
			
			String signatureValue = (String) rootStructure.get(JWSConstants.SIGNATURE);
			assertNotNull(signatureValue);
			assertTrue(DSSJsonUtils.isBase64UrlEncoded(signatureValue));
			assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(signatureValue)));
			
			Map<String, Object> unprotected = (Map<String, Object>) rootStructure.get(JWSConstants.HEADER);
			assertTrue(Utils.isMapNotEmpty(unprotected));

			List<?> etsiUValues = (List<?>) unprotected.get(JAdESHeaderParameterNames.ETSI_U);
			assertNotNull(etsiUValues);
			assertEquals(1, etsiUValues.size());

			Map<String, Object> sigTst = DSSJsonUtils.parseEtsiUComponent(etsiUValues.get(0));
			assertEquals(1, sigTst.size());

			Map<String, Object> tstTokens = (Map<String, Object>) sigTst.get(JAdESHeaderParameterNames.SIG_TST);
			assertNotNull(tstTokens);
			assertEquals(1, tstTokens.size());

			List<?> tstVals = (List<?>) tstTokens.get(JAdESHeaderParameterNames.TST_TOKENS);
			assertNotNull(tstVals);
			assertEquals(1, tstVals.size());

			Map<String, Object> tstVal = (Map<String, Object>) tstVals.get(0);
			assertEquals(1, tstVal.size());

			String sigTstValue = (String) tstVal.get(JAdESHeaderParameterNames.VAL);
			assertNotNull(sigTstValue);
			assertTrue(Utils.isBase64Encoded(sigTstValue));

			SignedDocumentValidator tstValidator = DetachedTimestampValidator.fromDocument(new InMemoryDocument(Utils.fromBase64(sigTstValue)));
			tstValidator.setCertificateVerifier(getOfflineCertificateVerifier());
			tstValidator.setDetachedContents(Arrays.asList(new InMemoryDocument(signatureValue.getBytes())));
			Reports reports = tstValidator.validateDocument();
			DiagnosticData diagnosticData = reports.getDiagnosticData();

			assertEquals(0, diagnosticData.getSignatures().size());
			assertEquals(1, diagnosticData.getTimestampList().size());
			TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().get(0);
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			assertTrue(timestampWrapper.isSignatureIntact());
			assertTrue(timestampWrapper.isSignatureValid());

		} catch (JoseException e) {
			fail("Unable to parse the signed file : " + e.getMessage());
		}
		
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
