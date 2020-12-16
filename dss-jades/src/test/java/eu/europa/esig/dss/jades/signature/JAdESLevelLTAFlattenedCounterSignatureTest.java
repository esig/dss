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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;

public class JAdESLevelLTAFlattenedCounterSignatureTest extends AbstractJAdESCounterSignatureTest {

	private JAdESService service;
	private DSSDocument documentToSign;
	private JAdESSignatureParameters signatureParameters;
	private JAdESCounterSignatureParameters counterSignatureParameters;

	@BeforeEach
	public void init() throws Exception {
		service = new JAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		
		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
		signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
		
		counterSignatureParameters = new JAdESCounterSignatureParameters();
		counterSignatureParameters.bLevel().setSigningDate(new Date());
		counterSignatureParameters.setSigningCertificate(getSigningCert());
		counterSignatureParameters.setCertificateChain(getCertificateChain());
		counterSignatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
		counterSignatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		
		JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(new InMemoryDocument(byteArray));
		assertTrue(jwsJsonSerializationParser.isSupported());
		
		JWSJsonSerializationObject jsonSerializationObject = jwsJsonSerializationParser.parse();
		List<JWS> jwsSignatures = jsonSerializationObject.getSignatures();
		assertEquals(1, jwsSignatures.size());
		
		JWS jws = jwsSignatures.iterator().next();
		assertLTALevelFound(jws);
		
		boolean cSigFound = false;
		List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
		for (Object etsiUEntry : etsiU) {
			Map<?, ?> item = DSSJsonUtils.parseEtsiUComponent(etsiUEntry);
			assertEquals(1, item.size());
			
			Map<String, ?> cSig = (Map<String, ?>) item.get(JAdESHeaderParameterNames.C_SIG);
			if (cSig != null) {
				cSigFound = true;
				
				jwsJsonSerializationParser = new JWSJsonSerializationParser(new InMemoryDocument(JsonUtil.toJson(cSig).getBytes()));
				assertTrue(jwsJsonSerializationParser.isSupported());
				
				jsonSerializationObject = jwsJsonSerializationParser.parse();
				jwsSignatures = jsonSerializationObject.getSignatures();
				assertEquals(1, jwsSignatures.size());
				
				JWS counterJWS = jwsSignatures.iterator().next();
				assertLTALevelFound(counterJWS);
			}
		}
		assertTrue(cSigFound);
		
	}
	
	private void assertLTALevelFound(JWS jws) {
		boolean sigTstFound = false;
		boolean xValsFound = false;
		boolean rValsFound = false;
		boolean arcTstFound = false;
		
		List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
		for (Object etsiUEntry : etsiU) {
			Map<?, ?> item = DSSJsonUtils.parseEtsiUComponent(etsiUEntry);
			assertEquals(1, item.size());
			
			if (item.get(JAdESHeaderParameterNames.SIG_TST) != null) {
				sigTstFound = true;
			} else if (item.get(JAdESHeaderParameterNames.X_VALS) != null) {
				xValsFound = true;
			} else if (item.get(JAdESHeaderParameterNames.R_VALS) != null) {
				rValsFound = true;
			} else if (item.get(JAdESHeaderParameterNames.ARC_TST) != null) {
				arcTstFound = true;
			}
		}
		assertTrue(sigTstFound);
		assertTrue(xValsFound);
		assertTrue(rValsFound);
		assertTrue(arcTstFound);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);
		
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertEquals(SignatureLevel.JAdES_BASELINE_LTA, signatureWrapper.getSignatureFormat());
		}
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(4, diagnosticData.getTimestampList().size());
		
		int sigTstCounter = 0;
		int arcTstCounter = 0;
		for (TimestampWrapper timestampWrapper : timestampList) {
			assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
			
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				++sigTstCounter;
			} else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				++arcTstCounter;
			}
		}
		assertEquals(2, sigTstCounter);
		assertEquals(2, arcTstCounter);
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected JAdESCounterSignatureParameters getCounterSignatureParameters() {
		return counterSignatureParameters;
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
	protected CounterSignatureService<JAdESCounterSignatureParameters> getCounterSignatureService() {
		return service;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
