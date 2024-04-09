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
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.HTTPHeader;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.test.signature.AbstractCounterSignatureTest;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.JoseException;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractJAdESCounterSignatureTest extends AbstractCounterSignatureTest<JAdESSignatureParameters, 
				JAdESTimestampParameters, JAdESCounterSignatureParameters> {

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}
	
	@Override
	@SuppressWarnings("unchecked")
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		for (AdvancedSignature signature : signatures) {
			assertTrue(signature instanceof JAdESSignature);
			JAdESSignature jadesSignature = (JAdESSignature) signature;

			JWS jws = jadesSignature.getJws();
			
			try {
				Headers headers = jws.getHeaders();
				Map<String, Object> signedHeaders = JsonUtil.parseJson(headers.getFullHeaderAsJsonString());
				
				Set<String> keySet = signedHeaders.keySet();
				assertTrue(Utils.isCollectionNotEmpty(keySet));
				for (String signedPropertyName : keySet) {
					assertTrue(DSSJsonUtils.getSupportedProtectedCriticalHeaders().contains(signedPropertyName) ||
							DSSJsonUtils.isCriticalHeaderException(signedPropertyName));
				}
				
				Object crit = signedHeaders.get(HeaderParameterNames.CRITICAL);
				assertTrue(crit instanceof List<?>);
				
				List<String> critArray = (List<String>) crit;
				assertTrue(Utils.isCollectionNotEmpty(critArray));
				for (String critItem : critArray) {
					assertTrue(DSSJsonUtils.getSupportedProtectedCriticalHeaders().contains(critItem));
					assertFalse(DSSJsonUtils.isCriticalHeaderException(critItem));
				}
				
			} catch (JoseException e) {
				fail(e);
			}
			
		}
	}

	@Override
	protected MimeType getExpectedMime() {
		if (JWSSerializationType.COMPACT_SERIALIZATION.equals(getSignatureParameters().getJwsSerializationType())) {
			return MimeTypeEnum.JOSE;
		} else {
			return MimeTypeEnum.JOSE_JSON;
		}
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.JAdES_BASELINE_LTA.equals(signatureLevel)
				|| SignatureLevel.JAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.JAdES_BASELINE_T.equals(signatureLevel);
	}


	@Override
	protected boolean isBaselineLTA() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.JAdES_BASELINE_LTA.equals(signatureLevel);
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);

		Set<SignatureWrapper> allCounterSignatures = diagnosticData.getAllCounterSignatures();
		assertTrue(Utils.isCollectionNotEmpty(allCounterSignatures));
		for (SignatureWrapper signatureWrapper : allCounterSignatures) {
			boolean jwsSignatureInputFound = false;
			boolean counterSignedSignatureValueFound = false;
			for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
				if (DigestMatcherType.JWS_SIGNING_INPUT_DIGEST.equals(digestMatcher.getType())) {
					jwsSignatureInputFound = true;
				} else if (DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE.equals(digestMatcher.getType())) {
					counterSignedSignatureValueFound = true;
				}
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			}
			assertTrue(jwsSignatureInputFound);
			assertTrue(counterSignedSignatureValueFound);
		}
	}

	@Override
	protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
				if (DigestMatcherType.JWS_SIGNING_INPUT_DIGEST.equals(digestMatcher.getType()) ||
						DigestMatcherType.SIG_D_ENTRY.equals(digestMatcher.getType())) {
					assertNotNull(digestMatcher.getDigestMethod());
					assertNotNull(digestMatcher.getDigestValue());
				} else if (DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE.equals(digestMatcher.getType())) {
					assertNull(digestMatcher.getDigestMethod());
					assertNull(digestMatcher.getDigestValue());
				}
			}
		}
	}

	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNotNull(signatureWrapper.getSignatureValue());
		}
	}
	
	@Override
	protected void checkReportsSignatureIdentifier(Reports reports) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
			SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());
			
			SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
			assertNotNull(signatureIdentifier);
			
			assertNotNull(signatureIdentifier.getSignatureValue());
			assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
		}
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		for (String signatureId : signatureIdList) {

			List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
			assertTrue(Utils.isCollectionNotEmpty(retrievedOriginalDocuments));
			
			SignatureWrapper signature = diagnosticData.getSignatureById(signatureId);
			if (signature.isCounterSignature()) {
				continue;
			}
			
			List<DSSDocument> originalDocuments = getOriginalDocuments();
			for (DSSDocument original : originalDocuments) {
				boolean found = false;
				
				if (original instanceof HTTPHeader) {
					HTTPHeader httpHeaderDocument = (HTTPHeader) original;
					for (DSSDocument retrieved : retrievedOriginalDocuments) {
						if (retrieved instanceof HTTPHeader) {
							HTTPHeader retrievedDoc = (HTTPHeader) retrieved;
							if (Utils.areStringsEqual(httpHeaderDocument.getName(), retrievedDoc.getName()) && 
									Utils.areStringsEqual(httpHeaderDocument.getValue(), retrievedDoc.getValue())) {
								found = true;
							}
						}
					}
					
				} else {
					byte[] originalDigest = original.getDigestValue(DigestAlgorithm.SHA256);
					for (DSSDocument retrieved : retrievedOriginalDocuments) {
						byte[] retrievedDigest = retrieved.getDigestValue(DigestAlgorithm.SHA256);
						if (Arrays.equals(originalDigest, retrievedDigest)) {
							found = true;
						}
					}
					
				}
				
				assertTrue(found);
			}
		}
	}

}