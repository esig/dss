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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.validationreport.jaxb.SAMessageDigestType;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

public abstract class AbstractXAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> {

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		// Check for duplicate ids
		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(new InMemoryDocument(byteArray)));
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.XML;
	}

	@Override
	protected boolean isBaselineT() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.XAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.XAdES_BASELINE_LT.equals(signatureLevel)
				|| SignatureLevel.XAdES_BASELINE_T.equals(signatureLevel) || SignatureLevel.XAdES_T.equals(signatureLevel)
				|| SignatureLevel.XAdES_C.equals(signatureLevel) || SignatureLevel.XAdES_X.equals(signatureLevel)
				|| SignatureLevel.XAdES_XL.equals(signatureLevel) || SignatureLevel.XAdES_A.equals(signatureLevel);
	}

	@Override
	protected boolean isBaselineLTA() {
		SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
		return SignatureLevel.XAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.XAdES_A.equals(signatureLevel);
	}

	@Override
	protected void checkSignatureValue(DiagnosticData diagnosticData) {
		super.checkSignatureValue(diagnosticData);

		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.getEncryptionAlgorithm() != null && signatureWrapper.getDigestAlgorithm() != null &&
					signatureWrapper.getEncryptionAlgorithm().isEquivalent(EncryptionAlgorithm.ECDSA)) {
				assertFalse(DSSASN1Utils.isAsn1Encoded(signatureWrapper.getSignatureValue()), "PLAIN-ECDSA is expected!");
			}
		}
	}

	@Override
	protected void validateETSIMessageDigest(SAMessageDigestType md) {
		assertNull(md);
	}

	protected void verifySourcesAndDiagnosticDataWithOrphans(List<AdvancedSignature> signatures, DiagnosticData diagnosticData) {
		for (AdvancedSignature advancedSignature : signatures) {
			SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(advancedSignature.getId());

			SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
			FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();

			// Tokens
			assertEquals(certificateSource.getKeyInfoCertificates().size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.KEY_INFO).size());
			assertEquals(certificateSource.getCertificateValues().size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
			assertEquals(certificateSource.getTimeStampValidationDataCertValues().size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
			assertEquals(certificateSource.getAttrAuthoritiesCertValues().size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES).size());
			assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size()
					+ foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size());
			assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size()
					+ foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size());
			assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY).size()
					+ foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY).size());
			assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size()
					+ foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size());

			// Refs
			assertEquals(certificateSource.getSigningCertificateRefs().size(),
					foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
			assertEquals(0, foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS).size());
			assertEquals(certificateSource.getCompleteCertificateRefs().size(),
					foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size()
							+ foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());

			List<TimestampToken> timestamps = advancedSignature.getAllTimestamps();
			for (TimestampToken timestampToken : timestamps) {
				TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(timestampToken.getDSSIdAsString());

				certificateSource = timestampToken.getCertificateSource();
				foundCertificates = timestampWrapper.foundCertificates();

				// Tokens
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.KEY_INFO).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES).size());
				assertEquals(certificateSource.getSignedDataCertificates().size(),
						foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size());

				// Refs
				assertEquals(certificateSource.getSigningCertificateRefs().size(),
						foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
			}

			OfflineRevocationSource<OCSP> ocspSource = advancedSignature.getOCSPSource();
			Set<RevocationToken<OCSP>> allRevocationTokens = ocspSource.getAllRevocationTokens();
			for (RevocationToken<OCSP> revocationToken : allRevocationTokens) {
				RevocationCertificateSource revocationCertificateSource = revocationToken.getCertificateSource();
				if (revocationCertificateSource != null) {
					RevocationWrapper revocationWrapper = diagnosticData.getRevocationById(revocationToken.getDSSIdAsString());
					foundCertificates = revocationWrapper.foundCertificates();

					assertEquals(revocationCertificateSource.getCertificates().size(), foundCertificates.getRelatedCertificates().size());
					assertEquals(revocationCertificateSource.getAllCertificateRefs().size(), foundCertificates.getRelatedCertificateRefs().size());
				}
			}
		}
	}

}
