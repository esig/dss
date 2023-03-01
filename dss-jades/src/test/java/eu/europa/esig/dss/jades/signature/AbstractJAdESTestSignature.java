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

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.HTTPHeader;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.validation.JAdESCertificateSource;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SADataObjectFormatType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractJAdESTestSignature
		extends AbstractPkiFactoryTestDocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> {

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}
	
	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		if (JWSSerializationType.COMPACT_SERIALIZATION.equals(getSignatureParameters().getJwsSerializationType())) {
			for (byte b : byteArray) {
				assertFalse(DSSUtils.isLineBreakByte(b));
			}
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		for (AdvancedSignature signature : signatures) {
			assertTrue(signature instanceof JAdESSignature);
			JAdESSignature jadesSignature = (JAdESSignature) signature;

			JWS jws = jadesSignature.getJws();
			
			List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
			if (SignatureLevel.JAdES_BASELINE_B.equals(getSignatureParameters().getSignatureLevel())) {
				assertTrue(Utils.isCollectionEmpty(etsiU));
			} else {
				assertTrue(Utils.isCollectionNotEmpty(etsiU));

				if (getSignatureParameters().isBase64UrlEncodedEtsiUComponents()) {
					for (Object item : etsiU) {
						assertTrue(item instanceof String);
						assertTrue(DSSJsonUtils.isBase64UrlEncoded((String) item));
					}
				} else {
					for (Object item : etsiU) {
						assertTrue(item instanceof Map);
						assertEquals(1, ((Map<?, ?>) item).size());
					}
				}

			}

			Headers headers = jws.getHeaders();
			Set<String> keySet = DSSJsonUtils.extractJOSEHeaderMembersSet(jws);
			assertTrue(Utils.isCollectionNotEmpty(keySet));
			for (String signedPropertyName : keySet) {
				assertTrue(DSSJsonUtils.getSupportedProtectedCriticalHeaders().contains(signedPropertyName) ||
						DSSJsonUtils.isCriticalHeaderException(signedPropertyName) ||
						JAdESHeaderParameterNames.ETSI_U.equals(signedPropertyName));
			}

			Object crit = headers.getObjectHeaderValue(HeaderParameterNames.CRITICAL);
			assertTrue(crit instanceof List<?>);

			List<String> critArray = (List<String>) crit;
			assertTrue(Utils.isCollectionNotEmpty(critArray));
			for (String critItem : critArray) {
				assertTrue(DSSJsonUtils.getSupportedProtectedCriticalHeaders().contains(critItem));
				assertFalse(DSSJsonUtils.isCriticalHeaderException(critItem));
			}
		}
	}

	@Override
	protected void checkSignatureValue(DiagnosticData diagnosticData) {
		super.checkSignatureValue(diagnosticData);

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.getEncryptionAlgorithm() != null && signatureWrapper.getDigestAlgorithm() != null &&
					signatureWrapper.getEncryptionAlgorithm().isEquivalent(EncryptionAlgorithm.ECDSA)) {
				assertFalse(DSSASN1Utils.isAsn1EncodedSignatureValue(signatureWrapper.getSignatureValue()), "PLAIN-ECDSA is expected!");

				int bitLength = DSSASN1Utils.getSignatureValueBitLength(signatureWrapper.getSignatureValue());
				switch (signatureWrapper.getDigestAlgorithm()) {
					case SHA256:
						assertEquals(256, bitLength);
						break;
					case SHA384:
						assertEquals(384, bitLength);
						break;
					case SHA512:
						assertTrue(bitLength == 520 || bitLength == 528);
						break;
					default:
						fail(String.format("DigestAlgorithm '%s' is not supported for JWS with ECDSA!",
								signatureWrapper.getDigestAlgorithm()));
				}
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
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNotNull(signatureWrapper.getSignatureValue());
		}
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		super.checkSigningCertificateValue(diagnosticData);

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
			List<RelatedCertificateWrapper> signingCertificates = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
			assertEquals(1, signingCertificates.size());

			List<CertificateRefWrapper> references = signingCertificates.get(0).getReferences();
			List<RelatedCertificateWrapper> kidCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER);

			if (getSignatureParameters().isIncludeKeyIdentifier()) {
				assertEquals(2, references.size());
				assertEquals(1, kidCerts.size());
			} else {
				assertEquals(1, references.size());
				assertEquals(0, kidCerts.size());
			}

			for (CertificateRefWrapper certificateRef : references) {
				if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRef.getOrigin())) {
					assertNotNull(certificateRef.getDigestAlgoAndValue());
					assertNotNull(certificateRef.getDigestMethod());
					assertTrue(certificateRef.isDigestValuePresent());
					assertTrue(certificateRef.isDigestValueMatch());
					assertNull(certificateRef.getIssuerSerial());

				} else if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRef.getOrigin())) {
					assertNotNull(certificateRef.getCertificateId());
					assertNotNull(certificateRef.getIssuerSerial());
					assertTrue(certificateRef.isIssuerSerialPresent());
					assertTrue(certificateRef.isIssuerSerialMatch());
					assertNull(certificateRef.getDigestAlgoAndValue());
				}
			}
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
	protected void checkMimeType(DiagnosticData diagnosticData) {
		super.checkMimeType(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature.getMimeType());
		assertEquals(getExpectedMime(), MimeType.fromMimeTypeString(signature.getMimeType()));
	}

	@Override
	protected void validateETSIDataObjectFormatType(SADataObjectFormatType dataObjectFormat) {
		super.validateETSIDataObjectFormatType(dataObjectFormat);

		assertNotNull(dataObjectFormat.getMimeType());
		assertEquals(getExpectedMime(), MimeType.fromMimeTypeString(dataObjectFormat.getMimeType()));
	}

	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		for (String signatureId : signatureIdList) {

			List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
			assertTrue(Utils.isCollectionNotEmpty(retrievedOriginalDocuments));
			
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
					String originalDigest = original.getDigest(DigestAlgorithm.SHA256);
					for (DSSDocument retrieved : retrievedOriginalDocuments) {
						String retrievedDigest = retrieved.getDigest(DigestAlgorithm.SHA256);
						if (Utils.areStringsEqual(originalDigest, retrievedDigest)) {
							found = true;
						}
					}
					
				}
				
				assertTrue(found);
			}
		}
	}

	@Override
	protected void verifyCertificateSourceData(SignatureCertificateSource certificateSource, FoundCertificatesProxy foundCertificates) {
		super.verifyCertificateSourceData(certificateSource, foundCertificates);

		if (certificateSource instanceof JAdESCertificateSource) {
			JAdESCertificateSource jadesCertificateSource = (JAdESCertificateSource) certificateSource;
			assertEquals(jadesCertificateSource.getKeyIdentifierCertificates().size(),
					foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size() +
							foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());
			assertEquals(jadesCertificateSource.getKeyIdentifierCertificateRefs().size(),
					foundCertificates.getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size() +
							foundCertificates.getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());
		}
	}

}
