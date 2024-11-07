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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
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
import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampAnalyzer;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class JAdESLevelLTAFlattenedSerializationTest extends AbstractJAdESTestSignature {

	private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
	private DSSDocument documentToSign;
	private JAdESSignatureParameters signatureParameters;

	@BeforeEach
	void init() throws Exception {
		service = new JAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
		
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
			assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(signatureValue)));
			
			Map<String, Object> unprotected = (Map<String, Object>) rootStructure.get(JWSConstants.HEADER);
			assertTrue(Utils.isMapNotEmpty(unprotected));
			
			List<Object> unsignedProperties = (List<Object>) unprotected.get(JAdESHeaderParameterNames.ETSI_U);

			boolean xValsFound = false;
			boolean rValsFound = false;
			boolean arcTstFound = false;

			Object arcTstObject = null;
			String arcTstValue = null;
			
			for (Object property : unsignedProperties) {
				Map<?, ?> map = DSSJsonUtils.parseEtsiUComponent(property);
				List<?> xVals = (List<?>) map.get(JAdESHeaderParameterNames.X_VALS);
				if (xVals != null) {
					xValsFound = true;
				}
				Map<?, ?> rVals = (Map<?, ?>) map.get(JAdESHeaderParameterNames.R_VALS);
				if (rVals != null) {
					rValsFound = true;
				}
				Map<?, ?> arcTst = (Map<?, ?>) map.get(JAdESHeaderParameterNames.ARC_TST);
				if (arcTst != null) {
					arcTstObject = property;

					List<?> tstTokens = (List<?>) arcTst.get(JAdESHeaderParameterNames.TST_TOKENS);
					assertEquals(1, tstTokens.size());

					Map<?, ?> tstToken = (Map<?, ?>) tstTokens.get(0);
					arcTstValue = (String) tstToken.get(JAdESHeaderParameterNames.VAL);
					assertNotNull(arcTstValue);
					assertTrue(Utils.isBase64Encoded(arcTstValue));

					arcTstFound = true;
				}
			}
			
			assertTrue(xValsFound);
			assertTrue(rValsFound);
			assertTrue(arcTstFound);
			assertNotNull(arcTstObject);
			assertNotNull(arcTstValue);

			DocumentAnalyzer tstAnalyzer = DetachedTimestampAnalyzer.fromDocument(new InMemoryDocument(Utils.fromBase64(arcTstValue)));
			tstAnalyzer.setCertificateVerifier(getOfflineCertificateVerifier());

			StringBuilder arcTstMessageImprintBuilder = new StringBuilder();
			arcTstMessageImprintBuilder.append(payload);
			arcTstMessageImprintBuilder.append(".");
			arcTstMessageImprintBuilder.append(header).append(".");
			arcTstMessageImprintBuilder.append(signatureValue);
			arcTstMessageImprintBuilder.append(".");
			for (Object etsiUMember : unsignedProperties) {
				if (etsiUMember == arcTstObject) {
					break; // arcTst reached
				}
				arcTstMessageImprintBuilder.append((String) etsiUMember);
			}
			String arcTstMessageImprint = arcTstMessageImprintBuilder.toString();
			tstAnalyzer.setDetachedContents(Arrays.asList(new InMemoryDocument(arcTstMessageImprint.getBytes())));

			ValidationContext validationContext = tstAnalyzer.validate();
			assertEquals(0, validationContext.getProcessedSignatures().size());
			assertEquals(1, validationContext.getProcessedTimestamps().size());

			TimestampToken timestampToken = validationContext.getProcessedTimestamps().iterator().next();
			assertTrue(timestampToken.isMessageImprintDataFound());
			assertTrue(timestampToken.isMessageImprintDataIntact());
			assertTrue(timestampToken.isSignatureIntact());
			assertTrue(timestampToken.isValid());

		} catch (JoseException e) {
			fail("Unable to parse the signed file : " + e.getMessage());
		}
		
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
		assertEquals(0, foundCertificates.getOrphanCertificates().size());

		List<RelatedCertificateWrapper> relatedCertificates = foundCertificates.getRelatedCertificates();
		for (CertificateWrapper certificateWrapper : usedCertificates) {
			boolean found = false;
			for (RelatedCertificateWrapper relatedCertificateWrapper : relatedCertificates) {
				if (Utils.areStringsEqual(relatedCertificateWrapper.getId(), certificateWrapper.getId())) {
					found = true;
					break;
				}
			}
			assertTrue(found);
		}

		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper wrapper: allSignatures) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
		}

		for (CertificateWrapper wrapper: usedCertificates) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
		}

		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		for (RevocationWrapper wrapper : allRevocationData) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
		}

		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		for (TimestampWrapper wrapper : timestampList) {
			assertEquals(EncryptionAlgorithm.RSA, wrapper.getEncryptionAlgorithm());
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
