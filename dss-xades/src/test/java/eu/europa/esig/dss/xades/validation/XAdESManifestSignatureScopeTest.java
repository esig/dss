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
package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.util.List;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.TimestampCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.SignatureReferenceType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;

class XAdESManifestSignatureScopeTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/Signature-X-CZ_SEF-4.xml"));
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		super.checkBLevelValid(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(4, digestMatchers.size());
		
		boolean signedPropertiesFound = false;
		boolean keyInfoFound = false;
		boolean signaturePropertiesFound = false;
		boolean manifestFound = false;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			switch (digestMatcher.getType()) {
				case SIGNED_PROPERTIES:
					signedPropertiesFound = true;
					break;
				case KEY_INFO:
					keyInfoFound = true;
					break;
				case SIGNATURE_PROPERTIES:
					signaturePropertiesFound = true;
					break;
				case MANIFEST:
					manifestFound = true;
					break;
				default:
					fail("Unexpected DigestMatcherType: " + digestMatcher.getType());
			}
		}
		assertTrue(signedPropertiesFound);
		assertTrue(keyInfoFound);
		assertTrue(signaturePropertiesFound);
		assertTrue(manifestFound);
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		super.checkSignatureScopes(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		assertNotNull(signatureScopes);
		assertEquals(1, signatureScopes.size());
		
		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertNotNull(originalSignerDocuments);
		assertEquals(1, originalSignerDocuments.size());
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		List<TimestampToken> allTimestamps = advancedSignatures.get(0).getAllTimestamps();
		assertEquals(1, allTimestamps.size());
		TimestampToken timestampToken = allTimestamps.get(0);
		TimestampCertificateSource certificateSource = timestampToken.getCertificateSource();
		
		TimestampWrapper timestampById = diagnosticData.getTimestampById(timestampToken.getDSSIdAsString());
		assertNotNull(timestampById);
		FoundCertificatesProxy foundCertificates = timestampById.foundCertificates();
			
		assertEquals(certificateSource.getSigningCertificateRefs().size(),
				foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size() +
				foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		
		TimestampWrapper timestampWrapper = timestampList.get(0);
		assertTrue(timestampWrapper.isSigningCertificateIdentified());
		assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
		assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());
		
		CertificateRefWrapper signingCertificateReference = timestampWrapper.getSigningCertificateReference();
		assertNotNull(signingCertificateReference);
		assertTrue(signingCertificateReference.isDigestValuePresent());
		assertTrue(signingCertificateReference.isDigestValueMatch());
		assertTrue(signingCertificateReference.isIssuerSerialPresent());
		assertTrue(signingCertificateReference.isIssuerSerialMatch());
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(1, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);
		
		XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
		XmlSAV sav = signatureBBB.getSAV();
		
		I18nProvider i18nProvider = new I18nProvider();

		boolean signedPropertiesChecked = false;
		boolean keyInfoChecked = false;
		boolean signaturePropertiesChecked = false;
		boolean manifestChecked = false;
		for (XmlConstraint constraint : sav.getConstraint()) {
			String constraintNameString = constraint.getName().getValue();
			if (constraintNameString.equals(i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIGND_PRT))) {
				signedPropertiesChecked = true;
			} else if (constraintNameString.equals(i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_KEY))) {
				keyInfoChecked = true;
			} else if (constraintNameString.equals(i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIGNTR_PRT))) {
				signaturePropertiesChecked = true;
			} else if (constraintNameString.equals(i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_MAN))) {
				manifestChecked = true;
			}
		}
		
		assertTrue(signedPropertiesChecked);
		assertTrue(keyInfoChecked);
		assertTrue(signaturePropertiesChecked);
		assertTrue(manifestChecked);
		
	}
	
	@Override
	protected void validateETSISignatureValidationObjects(ValidationObjectListType signatureValidationObjects) {
		super.validateETSISignatureValidationObjects(signatureValidationObjects);
		
		int signedDataCounter = 0;
		int timestampCounter = 0;
		for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
			if (ObjectType.SIGNED_DATA.equals(validationObject.getObjectType())) {
				assertNotNull(validationObject.getId());
				assertNotNull(validationObject.getPOE());
				signedDataCounter++;
			} else if (ObjectType.TIMESTAMP.equals(validationObject.getObjectType())) {
				POEProvisioningType poeProvisioning = validationObject.getPOEProvisioning();
				List<SignatureReferenceType> signatureReferences = poeProvisioning.getSignatureReference();
				assertEquals(1, signatureReferences.size());
				SignatureReferenceType signatureReferenceType = signatureReferences.get(0);
				assertNotNull(signatureReferenceType.getDigestMethod());
				assertNotNull(signatureReferenceType.getDigestValue());
				assertNotNull(signatureReferenceType.getCanonicalizationMethod());
				assertNull(signatureReferenceType.getPAdESFieldName());
				timestampCounter++;
			}
		}
		assertEquals(1, signedDataCounter);
		assertEquals(1, timestampCounter);
	}

}
