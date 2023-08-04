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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.TokenIdentifierProvider;
import eu.europa.esig.dss.validation.UserFriendlyIdentifierProvider;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import eu.europa.esig.validationreport.jaxb.SACertIDListType;
import eu.europa.esig.validationreport.jaxb.SARevIDListType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

import javax.xml.bind.JAXBElement;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESWithValidationDataTstsTest extends AbstractJAdESTestValidation {

	private static final DSSDocument signedDocument = new FileDocument("src/test/resources/validation/jades-with-sigAndRefsTst-with-dot.json");

	@Override
	protected DSSDocument getSignedDocument() {
		return signedDocument;
	}
	
	@Override
	protected TokenIdentifierProvider getTokenIdentifierProvider() {
		return new UserFriendlyIdentifierProvider();
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);

		assertEquals(1, advancedSignatures.size());
		AdvancedSignature advancedSignature = advancedSignatures.get(0);
		
		SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
		assertEquals(2, certificateSource.getKeyInfoCertificates().size());
		
		List<CertificateRef> completeCertificateRefs = certificateSource.getCompleteCertificateRefs();
		assertEquals(3, completeCertificateRefs.size());
		for (CertificateRef certificateRef : completeCertificateRefs) {
			assertNotNull(certificateRef.getCertDigest());
			assertNotNull(certificateRef.getCertDigest().getAlgorithm());
			assertTrue(Utils.isArrayNotEmpty(certificateRef.getCertDigest().getValue()));
			
			assertNotNull(certificateRef.getCertificateIdentifier());
			assertNotNull(certificateRef.getCertificateIdentifier().getIssuerName());
			assertNotNull(certificateRef.getCertificateIdentifier().getSerialNumber());
		}
		
		List<CertificateRef> attributeCertificateRefs = certificateSource.getAttributeCertificateRefs();
		assertEquals(1, attributeCertificateRefs.size());
		for (CertificateRef certificateRef : attributeCertificateRefs) {
			assertNotNull(certificateRef.getCertDigest());
			assertNotNull(certificateRef.getCertDigest().getAlgorithm());
			assertTrue(Utils.isArrayNotEmpty(certificateRef.getCertDigest().getValue()));
			
			assertNotNull(certificateRef.getCertificateIdentifier());
			assertNotNull(certificateRef.getCertificateIdentifier().getIssuerName());
			assertNotNull(certificateRef.getCertificateIdentifier().getSerialNumber());
		}
		
		OfflineRevocationSource<CRL> crlSource = advancedSignature.getCRLSource();
		
		List<RevocationRef<CRL>> crlCompleteRefs = crlSource.getCompleteRevocationRefs();
		assertEquals(1, crlCompleteRefs.size());
		for (RevocationRef<CRL> crlRef : crlCompleteRefs) {
			assertTrue(crlRef instanceof CRLRef);
			assertNotNull(((CRLRef)crlRef).getCrlIssuer());
			assertNotNull(((CRLRef)crlRef).getCrlIssuedTime());
			
			assertNotNull(crlRef.getDigest());
			assertNotNull(crlRef.getDigest().getAlgorithm());
			assertTrue(Utils.isArrayNotEmpty(crlRef.getDigest().getValue()));
		}
		
		OfflineRevocationSource<OCSP> ocspSource = advancedSignature.getOCSPSource();
		
		List<RevocationRef<OCSP>> ocspCompleteRefs = ocspSource.getCompleteRevocationRefs();
		assertEquals(1, ocspCompleteRefs.size());
		for (RevocationRef<OCSP> ocspRef : ocspCompleteRefs) {
			assertTrue(ocspRef instanceof OCSPRef);
			
			assertNotNull(ocspRef.getDigest());
			assertNotNull(ocspRef.getDigest().getAlgorithm());
			assertTrue(Utils.isArrayNotEmpty(ocspRef.getDigest().getValue()));
		}
		
		checkOrphanTokens(diagnosticData);
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		FoundCertificatesProxy foundCertificates = signature.foundCertificates();
		assertEquals(2, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.KEY_INFO).size());
		assertEquals(3, foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
		assertEquals(1, foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS).size() +
				foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS).size());
		
		FoundRevocationsProxy foundRevocations = signature.foundRevocations();
		assertEquals(0, foundRevocations.getRelatedRevocationData().size());
		assertEquals(2, foundRevocations.getOrphanRevocationRefs().size());
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		assertEquals(4, diagnosticData.getTimestampList().size());
		boolean sigTstFound = false;
		boolean firstSigAndRfsTstFound = false;
		boolean secondSigAndRfsTstFound = false;
		boolean rfsTstFound = false;
		
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
				sigTstFound = true;
				
			} else if (TimestampType.VALIDATION_DATA_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
				assertEquals(1, timestampWrapper.getTimestampedTimestamps().size());
				assertEquals(2, timestampWrapper.getTimestampedOrphanRevocations().size());
				if (!firstSigAndRfsTstFound) {
					assertEquals(4, timestampWrapper.getTimestampedCertificates().size() +
							timestampWrapper.getTimestampedOrphanCertificates().size());
					firstSigAndRfsTstFound = true;
				} else {
					assertEquals(5, timestampWrapper.getTimestampedCertificates().size() +
							timestampWrapper.getTimestampedOrphanCertificates().size());
					secondSigAndRfsTstFound = true;
				}
				
			} else if (TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(4, timestampWrapper.getTimestampedCertificates().size() +
						timestampWrapper.getTimestampedOrphanCertificates().size());
				assertEquals(2, timestampWrapper.getTimestampedOrphanRevocations().size());
				rfsTstFound = true;
			}
		}
		assertTrue(sigTstFound);
		assertTrue(firstSigAndRfsTstFound);
		assertTrue(secondSigAndRfsTstFound);
		assertTrue(rfsTstFound);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	@Test
	public void validateStructure() throws Exception {

		assertTrue(DSSJsonUtils.isJsonDocument(signedDocument));

		Map<String, Object> rootStructure = JsonUtil.parseJson(new String(DSSUtils.toByteArray(signedDocument)));

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

		int sigRTstCounter = 0;
		int rfsTstCounter = 0;

		Object sigTstObject = null;
		Object xRefsObject = null;
		Object rRefsObject = null;
		Object axRefsObject = null;

		for (Object property : unsignedProperties) {
			Map<?, ?> map = DSSJsonUtils.parseEtsiUComponent(property);
			Map<?, ?> sigTst = (Map<?, ?>) map.get(JAdESHeaderParameterNames.SIG_TST);
			if (sigTst != null) {
				sigTstObject = property;
			}
			List<?> xRefs = (List<?>) map.get(JAdESHeaderParameterNames.X_REFS);
			if (xRefs != null) {
				xRefsObject = property;
			}
			Map<?, ?> rRefs = (Map<?, ?>) map.get(JAdESHeaderParameterNames.R_REFS);
			if (rRefs != null) {
				rRefsObject = property;
			}
			List<?> axRefs = (List<?>) map.get(JAdESHeaderParameterNames.AX_REFS);
			if (axRefs != null) {
				axRefsObject = property;
			}
			Map<?, ?> sigRTst = (Map<?, ?>) map.get(JAdESHeaderParameterNames.SIG_R_TST);
			if (sigRTst != null) {
				++sigRTstCounter;
				DSSDocument timestamp = getTimestamp(sigRTst);

				StringBuilder messageImprintBuilder = new StringBuilder();
				messageImprintBuilder.append(signatureValue);
				messageImprintBuilder.append(".");
				messageImprintBuilder.append(getObjectsConcatenation(sigTstObject, xRefsObject, rRefsObject, axRefsObject));
				String messageImprint = messageImprintBuilder.toString();

				validateTimestamp(timestamp, new InMemoryDocument(messageImprint.getBytes()));
			}
			Map<?, ?> rfsTst = (Map<?, ?>) map.get(JAdESHeaderParameterNames.RFS_TST);
			if (rfsTst != null) {
				++rfsTstCounter;
				DSSDocument timestamp = getTimestamp(rfsTst);

				StringBuilder messageImprintBuilder = new StringBuilder();
				messageImprintBuilder.append(getObjectsConcatenation(xRefsObject, rRefsObject, axRefsObject));
				String messageImprint = messageImprintBuilder.toString();

				validateTimestamp(timestamp, new InMemoryDocument(messageImprint.getBytes()));
			}
		}

		assertEquals(2, sigRTstCounter);
		assertEquals(1, rfsTstCounter);

	}

	private DSSDocument getTimestamp(Map<?, ?> etsiUPropertyValue) {
		List<?> tstTokens = (List<?>) etsiUPropertyValue.get(JAdESHeaderParameterNames.TST_TOKENS);
		assertEquals(1, tstTokens.size());

		Map<?, ?> tstToken = (Map<?, ?>) tstTokens.get(0);
		String tstValue = (String) tstToken.get(JAdESHeaderParameterNames.VAL);
		assertNotNull(tstValue);
		assertTrue(Utils.isBase64Encoded(tstValue));

		return new InMemoryDocument(Utils.fromBase64(tstValue));
	}

	private String getObjectsConcatenation(Object... properties) {
		StringBuilder stringBuilder = new StringBuilder();
		for (Object property : properties) {
			if (property != null) {
				stringBuilder.append((String) property);
			}
		}
		return stringBuilder.toString();
	}

	private void validateTimestamp(DSSDocument timestamp, DSSDocument messageImprint) {
		SignedDocumentValidator tstValidator = DetachedTimestampValidator.fromDocument(timestamp);
		tstValidator.setCertificateVerifier(getOfflineCertificateVerifier());
		tstValidator.setDetachedContents(Arrays.asList(messageImprint));

		Reports reports = tstValidator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(0, diagnosticData.getSignatures().size());
		assertEquals(1, diagnosticData.getTimestampList().size());

		TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().get(0);
		assertTrue(timestampWrapper.isMessageImprintDataFound());
		assertTrue(timestampWrapper.isMessageImprintDataIntact());
		assertTrue(timestampWrapper.isSignatureIntact());
		assertTrue(timestampWrapper.isSignatureValid());
	}

	@Override
	protected void validateETSISignatureAttributes(SignatureAttributesType signatureAttributes) {
		super.validateETSISignatureAttributes(signatureAttributes);

		boolean signCertRefFound = false;
		boolean completeCertRefFound = false;
		boolean completeRevocRefFound = false;
		boolean attributeCertRefFound = false;

		List<Object> signatureAttributeObjects = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
		for (Object signatureAttributeObj : signatureAttributeObjects) {
			if (signatureAttributeObj instanceof JAXBElement) {
				JAXBElement jaxbElement = (JAXBElement) signatureAttributeObj;
				String xmlElementName = jaxbElement.getName().getLocalPart();
				if ("SigningCertificate".equals(xmlElementName)) {
					SACertIDListType certIdList = (SACertIDListType) jaxbElement.getValue();
					assertTrue(certIdList.isSigned());
					assertEquals(1, certIdList.getAttributeObject().size());
					assertEquals(1, certIdList.getAttributeObject().get(0).getVOReference().size());
					signCertRefFound = true;
				}
				if ("CompleteCertificateRefs".equals(xmlElementName)) {
					SACertIDListType certIdList = (SACertIDListType) jaxbElement.getValue();
					assertEquals(1, certIdList.getAttributeObject().size());
					assertEquals(3, certIdList.getAttributeObject().get(0).getVOReference().size());
					completeCertRefFound = true;
				}
				if ("CompleteRevocationRefs".equals(xmlElementName)) {
					SARevIDListType revIdList = (SARevIDListType) jaxbElement.getValue();
					assertEquals(0, revIdList.getAttributeObject().size());
					assertEquals(2, revIdList.getCRLIDOrOCSPID().size());
					completeRevocRefFound = true;
				}
				if ("AttributeCertificateRefs".equals(xmlElementName)) {
					SACertIDListType certIdList = (SACertIDListType) jaxbElement.getValue();
					assertEquals(0, certIdList.getAttributeObject().size());
					assertEquals(1, certIdList.getCertID().size());
					attributeCertRefFound = true;
				}
			}
		}
		assertTrue(signCertRefFound);
		assertTrue(completeCertRefFound);
		assertTrue(completeRevocRefFound);
		assertTrue(attributeCertRefFound);

	}

}
