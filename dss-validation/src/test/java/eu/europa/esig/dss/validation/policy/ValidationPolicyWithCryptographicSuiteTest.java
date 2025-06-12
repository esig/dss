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
package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.policy.CryptographicConstraintWrapper;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.ContainerConstraints;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.EIDAS;
import eu.europa.esig.dss.policy.jaxb.EvidenceRecordConstraints;
import eu.europa.esig.dss.policy.jaxb.IntValueConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.PDFAConstraints;
import eu.europa.esig.dss.policy.jaxb.RevocationConstraints;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.SignedAttributesConstraints;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.policy.jaxb.UnsignedAttributesConstraints;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidationPolicyWithCryptographicSuiteTest {

    @Test
    void constraintsTest() {
        ConstraintsParameters constraintsParameters = new ConstraintsParameters();
        EtsiValidationPolicy etsiValidationPolicy = new EtsiValidationPolicy(constraintsParameters);
        ValidationPolicyWithCryptographicSuite policy = new ValidationPolicyWithCryptographicSuite(etsiValidationPolicy);

        // --- General info ---
        assertNull(policy.getPolicyName());
        assertNull(policy.getPolicyDescription());

        constraintsParameters.setName("HelloWorld");
        constraintsParameters.setDescription("Test policy");

        assertEquals("HelloWorld", policy.getPolicyName());
        assertEquals("Test policy", policy.getPolicyDescription());

        // --- Signature Constraints ---
        SignatureConstraints signatureConstraints = new SignatureConstraints();
        constraintsParameters.setSignatureConstraints(signatureConstraints);

        assertNull(policy.getSignaturePolicyConstraint(Context.SIGNATURE));
        assertNull(policy.getSignaturePolicyIdentifiedConstraint(Context.SIGNATURE));
        assertNull(policy.getSignaturePolicyStorePresentConstraint(Context.SIGNATURE));
        assertNull(policy.getSignaturePolicyPolicyHashValid(Context.SIGNATURE));
        assertNull(policy.getSignatureFormatConstraint(Context.SIGNATURE));
        assertNull(policy.getStructuralValidationConstraint(Context.SIGNATURE));

        MultiValuesConstraint multi = new MultiValuesConstraint();
        multi.setLevel(Level.FAIL);
        signatureConstraints.setAcceptablePolicies(multi);
        signatureConstraints.setAcceptableFormats(multi);
        assertEquals(Level.FAIL, policy.getSignaturePolicyConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getSignatureFormatConstraint(Context.SIGNATURE).getLevel());

        LevelConstraint level = new LevelConstraint();
        level.setLevel(Level.FAIL);
        signatureConstraints.setPolicyAvailable(level);
        signatureConstraints.setSignaturePolicyStorePresent(level);
        signatureConstraints.setPolicyHashMatch(level);
        signatureConstraints.setStructuralValidation(level);

        assertEquals(Level.FAIL, policy.getSignaturePolicyIdentifiedConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getSignaturePolicyStorePresentConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getSignaturePolicyPolicyHashValid(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getStructuralValidationConstraint(Context.SIGNATURE).getLevel());

        // --- Basic Signature Constraints ---
        BasicSignatureConstraints basicConstraints = new BasicSignatureConstraints();
        signatureConstraints.setBasicSignatureConstraints(basicConstraints);

        assertNull(policy.getSignerInformationStoreConstraint(Context.SIGNATURE));
        assertNull(policy.getByteRangeConstraint(Context.SIGNATURE));
        assertNull(policy.getByteRangeCollisionConstraint(Context.SIGNATURE));
        assertNull(policy.getByteRangeAllDocumentConstraint(Context.SIGNATURE));
        assertNull(policy.getPdfSignatureDictionaryConstraint(Context.SIGNATURE));
        assertNull(policy.getPdfPageDifferenceConstraint(Context.SIGNATURE));
        assertNull(policy.getPdfAnnotationOverlapConstraint(Context.SIGNATURE));
        assertNull(policy.getPdfVisualDifferenceConstraint(Context.SIGNATURE));
        assertNull(policy.getDocMDPConstraint(Context.SIGNATURE));
        assertNull(policy.getFieldMDPConstraint(Context.SIGNATURE));
        assertNull(policy.getSigFieldLockConstraint(Context.SIGNATURE));
        assertNull(policy.getFormFillChangesConstraint(Context.SIGNATURE));
        assertNull(policy.getAnnotationChangesConstraint(Context.SIGNATURE));
        assertNull(policy.getUndefinedChangesConstraint(Context.SIGNATURE));
        assertNull(policy.getProspectiveCertificateChainConstraint(Context.SIGNATURE));
        assertNull(policy.getTrustServiceStatusConstraint(Context.SIGNATURE));
        assertNull(policy.getTrustServiceTypeIdentifierConstraint(Context.SIGNATURE));

        basicConstraints.setSignerInformationStore(level);
        basicConstraints.setByteRange(level);
        basicConstraints.setByteRangeCollision(level);
        basicConstraints.setByteRangeAllDocument(level);
        basicConstraints.setPdfSignatureDictionary(level);
        basicConstraints.setPdfPageDifference(level);
        basicConstraints.setPdfAnnotationOverlap(level);
        basicConstraints.setPdfVisualDifference(level);
        basicConstraints.setDocMDP(level);
        basicConstraints.setFieldMDP(level);
        basicConstraints.setSigFieldLock(level);
        basicConstraints.setFormFillChanges(level);
        basicConstraints.setAnnotationChanges(level);
        basicConstraints.setUndefinedChanges(level);
        basicConstraints.setProspectiveCertificateChain(level);
        basicConstraints.setTrustServiceStatus(multi);
        basicConstraints.setTrustServiceTypeIdentifier(multi);

        assertEquals(Level.FAIL, policy.getSignerInformationStoreConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getByteRangeConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getByteRangeCollisionConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getByteRangeAllDocumentConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getPdfSignatureDictionaryConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getPdfPageDifferenceConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getPdfAnnotationOverlapConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getPdfVisualDifferenceConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getDocMDPConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getFieldMDPConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getSigFieldLockConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getFormFillChangesConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getAnnotationChangesConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getUndefinedChangesConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getProspectiveCertificateChainConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getTrustServiceStatusConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getTrustServiceTypeIdentifierConstraint(Context.SIGNATURE).getLevel());

        // --- Signed Attributes Constraints ---
        SignedAttributesConstraints signedAttr = new SignedAttributesConstraints();
        signatureConstraints.setSignedAttributes(signedAttr);

        assertNull(policy.getContentTypeConstraint(Context.SIGNATURE));
        assertNull(policy.getContentHintsConstraint(Context.SIGNATURE));
        assertNull(policy.getContentIdentifierConstraint(Context.SIGNATURE));
        assertNull(policy.getContentTimeStampConstraint(Context.SIGNATURE));
        assertNull(policy.getContentTimeStampMessageImprintConstraint(Context.SIGNATURE));

        ValueConstraint valueConstraint = new ValueConstraint();
        valueConstraint.setLevel(Level.FAIL);

        signedAttr.setContentType(valueConstraint);
        signedAttr.setContentHints(valueConstraint);
        signedAttr.setContentIdentifier(valueConstraint);
        signedAttr.setContentTimeStamp(level);
        signedAttr.setContentTimeStampMessageImprint(level);

        assertEquals(Level.FAIL, policy.getContentTypeConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getContentHintsConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getContentIdentifierConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getContentTimeStampConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getContentTimeStampMessageImprintConstraint(Context.SIGNATURE).getLevel());

        signedAttr.setSigningCertificateRefersCertificateChain(level);
        signedAttr.setReferencesToAllCertificateChainPresent(level);
        signedAttr.setSigningCertificateDigestAlgorithm(level);
        signedAttr.setSigningTime(level);
        signedAttr.setMessageDigestOrSignedPropertiesPresent(level);
        signedAttr.setEllipticCurveKeySize(level);
        signedAttr.setSignerLocation(level);

        multi = new MultiValuesConstraint();
        multi.setLevel(Level.FAIL);
        signedAttr.setClaimedRoles(multi);
        signedAttr.setCertifiedRoles(multi);
        signedAttr.setCommitmentTypeIndication(multi);

        assertEquals(Level.FAIL, policy.getSigningCertificateRefersCertificateChainConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getReferencesToAllCertificateChainPresentConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getSigningCertificateDigestAlgorithmConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getSigningDurationRule(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getMessageDigestOrSignedPropertiesConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getEllipticCurveKeySizeConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getSignerLocationConstraint(Context.SIGNATURE).getLevel());

        assertEquals(Level.FAIL, policy.getClaimedRoleConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getCertifiedRolesConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getCommitmentTypeIndicationConstraint(Context.SIGNATURE).getLevel());

        // --- Unsigned Attributes Constraints ---
        UnsignedAttributesConstraints unsignedAttr = new UnsignedAttributesConstraints();
        signatureConstraints.setUnsignedAttributes(unsignedAttr);

        unsignedAttr.setCounterSignature(level);
        unsignedAttr.setSignatureTimeStamp(level);
        unsignedAttr.setValidationDataTimeStamp(level);
        unsignedAttr.setValidationDataRefsOnlyTimeStamp(level);
        unsignedAttr.setArchiveTimeStamp(level);
        unsignedAttr.setDocumentTimeStamp(level);
        unsignedAttr.setTLevelTimeStamp(level);
        unsignedAttr.setLTALevelTimeStamp(level);

        assertEquals(Level.FAIL, policy.getCounterSignatureConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getSignatureTimeStampConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getValidationDataTimeStampConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getValidationDataRefsOnlyTimeStampConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getArchiveTimeStampConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getDocumentTimeStampConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getTLevelTimeStampConstraint(Context.SIGNATURE).getLevel());
        assertEquals(Level.FAIL, policy.getLTALevelTimeStampConstraint(Context.SIGNATURE).getLevel());

        // --- Certificate Constraints ---
        CertificateConstraints certificateConstraints = new CertificateConstraints();
        basicConstraints.setSigningCertificate(certificateConstraints);

        // Null checks for all constraints
        assertNull(policy.getCertificateCAConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateIssuerNameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateMaxPathLengthConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateKeyUsageConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateExtendedKeyUsageConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificatePolicyTreeConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateNameConstraintsConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateNoRevAvailConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateSupportedCriticalExtensionsConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateForbiddenExtensionsConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateSurnameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateGivenNameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateCommonNameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificatePseudonymConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateTitleConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateEmailConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateCountryConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateLocalityConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateStateConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateOrganizationIdentifierConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateOrganizationNameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateOrganizationUnitConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificatePseudoUsageConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateSerialNumberConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateNotExpiredConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateSunsetDateConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateAuthorityInfoAccessPresentConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getRevocationDataSkipConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateRevocationInfoAccessPresentConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateSignatureConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getRevocationDataAvailableConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getAcceptableRevocationDataFoundConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCRLNextUpdatePresentConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getOCSPNextUpdatePresentConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getRevocationFreshnessConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getRevocationFreshnessNextUpdateConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateNotRevokedConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateNotOnHoldConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getRevocationIssuerNotExpiredConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateNotSelfSignedConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateSelfSignedConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificatePolicyIdsConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificatePolicyQualificationIdsConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificatePolicySupportedByQSCDIdsConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateQCComplianceConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateQcEuLimitValueCurrencyConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateMinQcEuLimitValueConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateMinQcEuRetentionPeriodConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateQcSSCDConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateQcEuPDSLocationConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateQcTypeConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateQcCCLegislationConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateIssuedToNaturalPersonConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateIssuedToLegalPersonConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificateSemanticsIdentifierConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificatePS2DQcTypeRolesOfPSPConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificatePS2DQcCompetentAuthorityNameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));
        assertNull(policy.getCertificatePS2DQcCompetentAuthorityIdConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT));

        certificateConstraints.setCA(level);
        certificateConstraints.setIssuerName(level);
        certificateConstraints.setMaxPathLength(level);
        certificateConstraints.setKeyUsage(multi);
        certificateConstraints.setExtendedKeyUsage(multi);
        certificateConstraints.setPolicyTree(level);
        certificateConstraints.setNameConstraints(level);
        certificateConstraints.setNoRevAvail(level);
        certificateConstraints.setSupportedCriticalExtensions(multi);
        certificateConstraints.setForbiddenExtensions(multi);
        certificateConstraints.setSurname(multi);
        certificateConstraints.setGivenName(multi);
        certificateConstraints.setCommonName(multi);
        certificateConstraints.setPseudonym(multi);
        certificateConstraints.setTitle(multi);
        certificateConstraints.setEmail(multi);
        certificateConstraints.setCountry(multi);
        certificateConstraints.setLocality(multi);
        certificateConstraints.setState(multi);
        certificateConstraints.setOrganizationIdentifier(multi);
        certificateConstraints.setOrganizationName(multi);
        certificateConstraints.setOrganizationUnit(multi);
        certificateConstraints.setUsePseudonym(level);
        certificateConstraints.setSerialNumberPresent(level);
        certificateConstraints.setNotExpired(level);
        certificateConstraints.setSunsetDate(level);
        certificateConstraints.setAuthorityInfoAccessPresent(level);
        certificateConstraints.setRevocationInfoAccessPresent(level);
        certificateConstraints.setSignature(level);
        certificateConstraints.setRevocationDataAvailable(level);
        certificateConstraints.setAcceptableRevocationDataFound(level);
        certificateConstraints.setCRLNextUpdatePresent(level);
        certificateConstraints.setOCSPNextUpdatePresent(level);
        certificateConstraints.setRevocationFreshnessNextUpdate(level);
        certificateConstraints.setNotRevoked(level);
        certificateConstraints.setNotOnHold(level);
        certificateConstraints.setRevocationIssuerNotExpired(level);
        certificateConstraints.setNotSelfSigned(level);
        certificateConstraints.setSelfSigned(level);
        certificateConstraints.setPolicyQualificationIds(level);
        certificateConstraints.setPolicySupportedByQSCDIds(level);
        certificateConstraints.setQcCompliance(level);
        certificateConstraints.setQcSSCD(level);
        certificateConstraints.setIssuedToNaturalPerson(level);
        certificateConstraints.setIssuedToLegalPerson(level);

        CertificateValuesConstraint certificateLevel = new CertificateValuesConstraint();
        certificateLevel.setLevel(Level.FAIL);
        certificateConstraints.setRevocationDataSkip(certificateLevel);

        TimeConstraint timeLevel = new TimeConstraint();
        timeLevel.setLevel(Level.FAIL);
        certificateConstraints.setRevocationFreshness(timeLevel);
        
        // Set up and test MultiValuesConstraint values
        multi = new MultiValuesConstraint();
        multi.setLevel(Level.FAIL);
        multi.getId().addAll(Arrays.asList("1", "2"));

        certificateConstraints.setPolicyIds(multi);
        certificateConstraints.setQcEuPDSLocation(multi);
        certificateConstraints.setQcType(multi);
        certificateConstraints.setQcLegislationCountryCodes(multi);
        certificateConstraints.setSemanticsIdentifier(multi);
        certificateConstraints.setPSD2QcTypeRolesOfPSP(multi);
        certificateConstraints.setPSD2QcCompetentAuthorityName(multi);
        certificateConstraints.setPSD2QcCompetentAuthorityId(multi);

        assertEquals(Arrays.asList("1", "2"), policy.getCertificatePolicyIdsConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getValues());
        assertEquals(Arrays.asList("1", "2"), policy.getCertificateQcEuPDSLocationConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getValues());
        assertEquals(Arrays.asList("1", "2"), policy.getCertificateQcTypeConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getValues());
        assertEquals(Arrays.asList("1", "2"), policy.getCertificateQcCCLegislationConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getValues());
        assertEquals(Arrays.asList("1", "2"), policy.getCertificateSemanticsIdentifierConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getValues());
        assertEquals(Arrays.asList("1", "2"), policy.getCertificatePS2DQcTypeRolesOfPSPConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getValues());
        assertEquals(Arrays.asList("1", "2"), policy.getCertificatePS2DQcCompetentAuthorityNameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getValues());
        assertEquals(Arrays.asList("1", "2"), policy.getCertificatePS2DQcCompetentAuthorityIdConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getValues());


        // Set up and test ValueConstraint
        ValueConstraint valueLevel = new ValueConstraint();
        valueLevel.setLevel(Level.FAIL);
        valueLevel.setValue("1000");
        certificateConstraints.setQcEuLimitValueCurrency(valueLevel);

        assertEquals("1000", policy.getCertificateQcEuLimitValueCurrencyConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getValue());
        
        // Set up and test NumericValueConstraint
        IntValueConstraint numericLevel = new IntValueConstraint();
        numericLevel.setLevel(Level.FAIL);
        numericLevel.setValue(10);
        certificateConstraints.setMinQcEuLimitValue(numericLevel);
        certificateConstraints.setMinQcEuRetentionPeriod(numericLevel);

        assertEquals(10, policy.getCertificateMinQcEuLimitValueConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getValue());
        assertEquals(10, policy.getCertificateMinQcEuRetentionPeriodConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getValue());

        // --- Validating Level for Certificate Constraints ---
        assertEquals(Level.FAIL, policy.getCertificateCAConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateIssuerNameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateMaxPathLengthConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateKeyUsageConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateExtendedKeyUsageConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificatePolicyTreeConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateNameConstraintsConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateNoRevAvailConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateSupportedCriticalExtensionsConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateForbiddenExtensionsConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateSurnameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateGivenNameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateCommonNameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificatePseudonymConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateTitleConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateEmailConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateCountryConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateLocalityConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateStateConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateOrganizationIdentifierConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateOrganizationNameConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateOrganizationUnitConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificatePseudoUsageConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateSerialNumberConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateNotExpiredConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateSunsetDateConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateAuthorityInfoAccessPresentConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getRevocationDataSkipConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateRevocationInfoAccessPresentConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateSignatureConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getRevocationDataAvailableConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getAcceptableRevocationDataFoundConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCRLNextUpdatePresentConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getOCSPNextUpdatePresentConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getRevocationFreshnessConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getRevocationFreshnessNextUpdateConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateNotRevokedConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateNotOnHoldConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getRevocationIssuerNotExpiredConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateNotSelfSignedConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateSelfSignedConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateIssuedToNaturalPersonConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());
        assertEquals(Level.FAIL, policy.getCertificateIssuedToLegalPersonConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getLevel());


        // --- Revocation constraints ---
        RevocationConstraints revocationConstraints = new RevocationConstraints();
        constraintsParameters.setRevocation(revocationConstraints);

        LevelConstraint ignoreLevel = new LevelConstraint();
        ignoreLevel.setLevel(Level.IGNORE);

        revocationConstraints.setUnknownStatus(ignoreLevel);
        revocationConstraints.setThisUpdatePresent(ignoreLevel);
        revocationConstraints.setRevocationIssuerKnown(ignoreLevel);
        revocationConstraints.setRevocationIssuerValidAtProductionTime(ignoreLevel);
        revocationConstraints.setRevocationAfterCertificateIssuance(ignoreLevel);
        revocationConstraints.setRevocationHasInformationAboutCertificate(ignoreLevel);
        revocationConstraints.setOCSPResponderIdMatch(ignoreLevel);
        revocationConstraints.setOCSPCertHashPresent(ignoreLevel);
        revocationConstraints.setOCSPCertHashMatch(ignoreLevel);
        revocationConstraints.setSelfIssuedOCSP(ignoreLevel);

        assertEquals(Level.IGNORE, policy.getUnknownStatusConstraint().getLevel());
        assertEquals(Level.IGNORE, policy.getThisUpdatePresentConstraint().getLevel());
        assertEquals(Level.IGNORE, policy.getRevocationIssuerKnownConstraint().getLevel());
        assertEquals(Level.IGNORE, policy.getRevocationIssuerValidAtProductionTimeConstraint().getLevel());
        assertEquals(Level.IGNORE, policy.getRevocationAfterCertificateIssuanceConstraint().getLevel());
        assertEquals(Level.IGNORE, policy.getRevocationHasInformationAboutCertificateConstraint().getLevel());
        assertEquals(Level.IGNORE, policy.getOCSPResponseResponderIdMatchConstraint().getLevel());
        assertEquals(Level.IGNORE, policy.getOCSPResponseCertHashPresentConstraint().getLevel());
        assertEquals(Level.IGNORE, policy.getOCSPResponseCertHashMatchConstraint().getLevel());
        assertEquals(Level.IGNORE, policy.getSelfIssuedOCSPConstraint().getLevel());

        revocationConstraints.setUnknownStatus(level);
        revocationConstraints.setThisUpdatePresent(level);
        revocationConstraints.setRevocationIssuerKnown(level);
        revocationConstraints.setRevocationIssuerValidAtProductionTime(level);
        revocationConstraints.setRevocationAfterCertificateIssuance(level);
        revocationConstraints.setRevocationHasInformationAboutCertificate(level);
        revocationConstraints.setOCSPResponderIdMatch(level);
        revocationConstraints.setOCSPCertHashPresent(level);
        revocationConstraints.setOCSPCertHashMatch(level);
        revocationConstraints.setSelfIssuedOCSP(level);

        assertEquals(Level.FAIL, policy.getUnknownStatusConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getThisUpdatePresentConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getRevocationIssuerKnownConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getRevocationIssuerValidAtProductionTimeConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getRevocationAfterCertificateIssuanceConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getRevocationHasInformationAboutCertificateConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getOCSPResponseResponderIdMatchConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getOCSPResponseCertHashPresentConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getOCSPResponseCertHashMatchConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getSelfIssuedOCSPConstraint().getLevel());

        // --- Timestamp Constraints ---
        TimestampConstraints timestampConstraints = new TimestampConstraints();
        constraintsParameters.setTimestamp(timestampConstraints);

        // Initially all should be null
        assertNull(policy.getBestSignatureTimeBeforeExpirationDateOfSigningCertificateConstraint());
        assertNull(policy.getRevocationTimeAgainstBestSignatureDurationRule());
        assertNull(policy.getTimestampCoherenceConstraint());
        assertNull(policy.getTimestampDelayConstraint());
        assertNull(policy.getTimestampValidConstraint());
        assertNull(policy.getTimestampTSAGeneralNamePresent());
        assertNull(policy.getTimestampTSAGeneralNameContentMatch());
        assertNull(policy.getTimestampTSAGeneralNameOrderMatch());
        assertNull(policy.getAtsHashIndexConstraint());
        assertNull(policy.getTimestampContainerSignedAndTimestampedFilesCoveredConstraint());

        timestampConstraints.setBestSignatureTimeBeforeExpirationDateOfSigningCertificate(level);
        timestampConstraints.setRevocationTimeAgainstBestSignatureTime(level);
        timestampConstraints.setCoherence(level);
        timestampConstraints.setTimestampValid(level);
        timestampConstraints.setTSAGeneralNamePresent(level);
        timestampConstraints.setTSAGeneralNameContentMatch(level);
        timestampConstraints.setTSAGeneralNameOrderMatch(level);
        timestampConstraints.setAtsHashIndex(level);
        timestampConstraints.setContainerSignedAndTimestampedFilesCovered(level);
        timestampConstraints.setTimestampDelay(timeLevel);

        assertEquals(Level.FAIL, policy.getBestSignatureTimeBeforeExpirationDateOfSigningCertificateConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getRevocationTimeAgainstBestSignatureDurationRule().getLevel());
        assertEquals(Level.FAIL, policy.getTimestampCoherenceConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getTimestampValidConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getTimestampTSAGeneralNamePresent().getLevel());
        assertEquals(Level.FAIL, policy.getTimestampTSAGeneralNameContentMatch().getLevel());
        assertEquals(Level.FAIL, policy.getTimestampTSAGeneralNameOrderMatch().getLevel());
        assertEquals(Level.FAIL, policy.getAtsHashIndexConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getTimestampContainerSignedAndTimestampedFilesCoveredConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getTimestampDelayConstraint().getLevel());

        // --- Evidence Record Constraints ---
        EvidenceRecordConstraints evidence = new EvidenceRecordConstraints();
        constraintsParameters.setEvidenceRecord(evidence);

        assertNull(policy.getEvidenceRecordValidConstraint());
        assertNull(policy.getEvidenceRecordDataObjectExistenceConstraint());
        assertNull(policy.getEvidenceRecordDataObjectIntactConstraint());
        assertNull(policy.getEvidenceRecordDataObjectFoundConstraint());
        assertNull(policy.getEvidenceRecordDataObjectGroupConstraint());
        assertNull(policy.getEvidenceRecordSignedFilesCoveredConstraint());
        assertNull(policy.getEvidenceRecordContainerSignedAndTimestampedFilesCoveredConstraint());
        assertNull(policy.getEvidenceRecordHashTreeRenewalConstraint());

        evidence.setEvidenceRecordValid(level);
        evidence.setDataObjectExistence(level);
        evidence.setDataObjectIntact(level);
        evidence.setDataObjectFound(level);
        evidence.setDataObjectGroup(level);
        evidence.setSignedFilesCovered(level);
        evidence.setContainerSignedAndTimestampedFilesCovered(level);
        evidence.setHashTreeRenewal(level);

        assertEquals(Level.FAIL, policy.getEvidenceRecordValidConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getEvidenceRecordDataObjectExistenceConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getEvidenceRecordDataObjectIntactConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getEvidenceRecordDataObjectFoundConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getEvidenceRecordDataObjectGroupConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getEvidenceRecordSignedFilesCoveredConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getEvidenceRecordContainerSignedAndTimestampedFilesCoveredConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getEvidenceRecordHashTreeRenewalConstraint().getLevel());

        // --- Container Constraints ---
        ContainerConstraints container = new ContainerConstraints();
        constraintsParameters.setContainerConstraints(container);

        assertNull(policy.getAcceptedContainerTypesConstraint());
        assertNull(policy.getZipCommentPresentConstraint());
        assertNull(policy.getAcceptedZipCommentsConstraint());
        assertNull(policy.getMimeTypeFilePresentConstraint());
        assertNull(policy.getAcceptedMimeTypeContentsConstraint());
        assertNull(policy.getAllFilesSignedConstraint());
        assertNull(policy.getManifestFilePresentConstraint());
        assertNull(policy.getSignedFilesPresentConstraint());

        container.setAcceptableContainerTypes(multi);
        container.setZipCommentPresent(level);
        container.setAcceptableZipComment(multi);
        container.setMimeTypeFilePresent(level);
        container.setAcceptableMimeTypeFileContent(multi);
        container.setAllFilesSigned(level);
        container.setManifestFilePresent(level);
        container.setSignedFilesPresent(level);

        assertEquals(Level.FAIL, policy.getAcceptedContainerTypesConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getAcceptedZipCommentsConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getAcceptedMimeTypeContentsConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getZipCommentPresentConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getMimeTypeFilePresentConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getAllFilesSignedConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getManifestFilePresentConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getSignedFilesPresentConstraint().getLevel());

        // --- PDFA Constraints ---
        PDFAConstraints pdfa = new PDFAConstraints();
        constraintsParameters.setPDFAConstraints(pdfa);

        assertNull(policy.getAcceptablePDFAProfilesConstraint());
        assertNull(policy.getPDFACompliantConstraint());

        pdfa.setAcceptablePDFAProfiles(multi);
        pdfa.setPDFACompliant(level);

        assertEquals(Level.FAIL, policy.getAcceptablePDFAProfilesConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getPDFACompliantConstraint().getLevel());

        // --- eIDAS constraints ---
        assertFalse(policy.isEIDASConstraintPresent());

        EIDAS eidas = new EIDAS();
        constraintsParameters.setEIDAS(eidas);

        assertTrue(policy.isEIDASConstraintPresent());
        assertNull(policy.getTLFreshnessConstraint());
        assertNull(policy.getTLWellSignedConstraint());
        assertNull(policy.getTLNotExpiredConstraint());
        assertNull(policy.getTLVersionConstraint());
        assertNull(policy.getTLStructureConstraint());

        eidas.setTLFreshness(timeLevel);
        eidas.setTLWellSigned(level);
        eidas.setTLNotExpired(level);
        eidas.setTLVersion(multi);
        eidas.setTLStructure(level);

        assertTrue(policy.isEIDASConstraintPresent());
        assertEquals(Level.FAIL, policy.getTLFreshnessConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getTLWellSignedConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getTLNotExpiredConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getTLVersionConstraint().getLevel());
        assertEquals(Level.FAIL, policy.getTLStructureConstraint().getLevel());
    }

    @Test
    void cryptoSuitesTest() {
        ConstraintsParameters constraintsParameters = new ConstraintsParameters();
        EtsiValidationPolicy etsiValidationPolicy = new EtsiValidationPolicy(constraintsParameters);
        ValidationPolicyWithCryptographicSuite policy = new ValidationPolicyWithCryptographicSuite(etsiValidationPolicy);

        for (Context context : Context.values()) {
            if (Context.EVIDENCE_RECORD != context) {
                assertEquals(Collections.emptyList(), policy.getSignatureCryptographicConstraint(context).getAcceptableDigestAlgorithms());
                for (SubContext subContext : SubContext.values()) {
                    assertEquals(Collections.emptyList(), policy.getCertificateCryptographicConstraint(context, subContext).getAcceptableDigestAlgorithms());
                }
            }
        }
        assertEquals(Collections.emptyList(), policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms());

        // default crypto suite
        CryptographicConstraint defaultCrypto = new CryptographicConstraint();
        defaultCrypto.setLevel(Level.FAIL);
        ListAlgo listAlgo = new ListAlgo();
        Algo algo = new Algo();
        algo.setValue("SHA1");
        listAlgo.getAlgos().add(algo);
        defaultCrypto.setAcceptableDigestAlgo(listAlgo);

        constraintsParameters.setCryptographic(defaultCrypto);

        List<DigestAlgorithm> sha1List = Collections.singletonList(DigestAlgorithm.SHA1);
        for (Context context : Context.values()) {
            if (Context.EVIDENCE_RECORD != context) {
                assertEquals(sha1List, policy.getSignatureCryptographicConstraint(context).getAcceptableDigestAlgorithms());
                for (SubContext subContext : SubContext.values()) {
                    assertEquals(sha1List, policy.getCertificateCryptographicConstraint(context, subContext).getAcceptableDigestAlgorithms());
                }
            }
        }
        assertEquals(sha1List, policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms());

        // default crypto suite
        CryptographicConstraint altCrypto = new CryptographicConstraint();
        altCrypto.setLevel(Level.FAIL);
        listAlgo = new ListAlgo();
        algo = new Algo();
        algo.setValue("SHA256");
        listAlgo.getAlgos().add(algo);
        altCrypto.setAcceptableDigestAlgo(listAlgo);

        CryptographicSuite altCryptoSuite = new CryptographicConstraintWrapper(altCrypto);
        policy.setCryptographicSuite(altCryptoSuite);

        List<DigestAlgorithm> sha256List = Collections.singletonList(DigestAlgorithm.SHA256);
        for (Context context : Context.values()) {
            if (Context.EVIDENCE_RECORD != context) {
                assertEquals(sha256List, policy.getSignatureCryptographicConstraint(context).getAcceptableDigestAlgorithms());
                for (SubContext subContext : SubContext.values()) {
                    assertEquals(sha256List, policy.getCertificateCryptographicConstraint(context, subContext).getAcceptableDigestAlgorithms());
                }
            }
        }
        assertEquals(sha256List, policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms());

        for (Context context : Context.values()) {
            policy = new ValidationPolicyWithCryptographicSuite(etsiValidationPolicy);
            policy.setCryptographicSuite(new CryptographicConstraintWrapper(altCrypto), context);

            for (Context currentContext : Context.values()) {
                if (Context.EVIDENCE_RECORD == currentContext) {
                    if (context == currentContext) {
                        assertEquals(sha256List, policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms());
                    } else {
                        assertEquals(sha1List, policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms());
                    }

                } else {
                    if (context == currentContext) {
                        assertEquals(sha256List, policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms());
                        assertEquals(sha256List, policy.getCertificateCryptographicConstraint(currentContext, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms());
                        assertEquals(sha256List, policy.getCertificateCryptographicConstraint(currentContext, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms());
                    } else {
                        assertEquals(sha1List, policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms());
                        assertEquals(sha1List, policy.getCertificateCryptographicConstraint(currentContext, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms());
                        assertEquals(sha1List, policy.getCertificateCryptographicConstraint(currentContext, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms());
                    }
                }
            }
        }

        for (Context context : Context.values()) {
            for (SubContext subContext : SubContext.values()) {
                if (Context.EVIDENCE_RECORD != context) {
                    policy = new ValidationPolicyWithCryptographicSuite(etsiValidationPolicy);
                    policy.setCryptographicSuite(new CryptographicConstraintWrapper(altCrypto), context, subContext);

                    for (Context currentContext : Context.values()) {
                        if (Context.EVIDENCE_RECORD != currentContext) {
                            for (SubContext currentSubContext : SubContext.values()) {
                                if (context == currentContext && subContext == currentSubContext) {
                                    assertEquals(sha1List, policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms());
                                    assertEquals(sha256List, policy.getCertificateCryptographicConstraint(currentContext, currentSubContext).getAcceptableDigestAlgorithms());
                                } else {
                                    assertEquals(sha1List, policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms());
                                    assertEquals(sha1List, policy.getCertificateCryptographicConstraint(currentContext, currentSubContext).getAcceptableDigestAlgorithms());
                                }
                            }
                        }
                    }
                }
            }
        }

        ValidationPolicyWithCryptographicSuite erPolicy = new ValidationPolicyWithCryptographicSuite(etsiValidationPolicy);
        Exception exception = assertThrows(IllegalArgumentException.class, () -> erPolicy.setCryptographicSuite(
                new CryptographicConstraintWrapper(altCrypto), Context.EVIDENCE_RECORD, SubContext.SIGNING_CERT));
        assertEquals("Please use a NULL SubContext for the Context.EVIDENCE_RECORD or " +
                "use #setCryptographicSuite(cryptographicSuite, context) method.", exception.getMessage());
    }

}
