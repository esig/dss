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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.attestation.common.creation.AttestationPresentationService;
import eu.europa.esig.dss.attestation.common.creation.TokenStatusList;
import eu.europa.esig.dss.attestation.common.validation.AbstractAttestationPresentationTestCreation;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDrivingPrivilege;
import eu.europa.esig.dss.attestation.mdoc.validation.MdocDeviceResponseDocumentValidator;
import eu.europa.esig.dss.attestation.mdoc.validation.MdocValidationParameters;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.COSESign;
import eu.europa.esig.dss.cbades.COSESign1;
import eu.europa.esig.dss.cbades.COSEUnprotectedHeader;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORSimpleObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.CBAdESUHeaders;
import eu.europa.esig.dss.cbades.validation.CBORSignature;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegeClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegeCodeClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegesClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.AttestationDocumentFormat;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.BaselineBCertificateSelector;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractMdocDeviceResponseTestCreation extends AbstractAttestationPresentationTestCreation
        <CBAdESSignatureParameters, MdocPayloadParameters, MdocIssuerSignedItem, MdocKeyBindingParameters> {

    @Override
    protected MdocService getService() {
        return new MdocService(getOfflineCertificateVerifier());
    }

    @Override
    protected AttestationPresentationService<CBAdESSignatureParameters, MdocIssuerSignedItem, MdocKeyBindingParameters> getPresentationService() {
        return new MdocService(getOfflineCertificateVerifier());
    }

    @Override
    protected MimeType getExpectedMime() {
        return MimeTypeEnum.CBOR;
    }

    @Override
    protected AttestationProfile getAttestationType() {
        return AttestationProfile.ISO_IEC_MDOC;
    }

    @Override
    protected AttestationDocumentFormat getAttestationPresentationType() {
        return AttestationDocumentFormat.MDOC_DEVICE_RESPONSE;
    }

    @Override
    protected boolean keyBindingPresent() {
        return true;
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        MdocDeviceResponseDocumentValidator mdocValidator = assertInstanceOf(MdocDeviceResponseDocumentValidator.class, validator);
        MdocValidationParameters mdocValidationParameters = new MdocValidationParameters();
        mdocValidationParameters.setSessionTranscript(buildSessionTranscript());
        mdocValidator.setAttestationValidationParameters(mdocValidationParameters);
        return validator;
    }

    @Override
    @SuppressWarnings("unchecked")
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        for (AdvancedSignature signature : signatures) {
            assertInstanceOf(CBAdESSignature.class, signature);
            CBAdESSignature cbadesSignature = (CBAdESSignature) signature;

            CBORSignature cose = cbadesSignature.getCoseSignature();

            CBAdESUHeaders cbAdESUHeaders = new CBAdESUHeaders(cose);
            assertFalse(cbAdESUHeaders.isExist());

            assertNotNull(cose.getContext());
            assertEquals(COSESignatureType.COSE_SIGN1, cose.getContext());

            assertNotNull(cose.getCoseSignStructure());
            assertEquals(COSEStructureType.COSE_SIGN == getSignatureParameters().getCoseStructureType(),
                    cose.getCoseSignStructure() instanceof COSESign);
            assertInstanceOf(COSESign1.class, cose.getCoseSignStructure());

            assertFalse(cose.isTagged());

            COSEProtectedHeader bodyProtectedHeader = cose.getBodyProtectedHeader();
            COSEProtectedHeader signerProtectedHeader = cose.getSignerProtectedHeader();

            COSEUnprotectedHeader bodyUnprotectedHeader = cose.getBodyUnprotectedHeader();
            COSEUnprotectedHeader signerUnprotectedHeader = cose.getSignerUnprotectedHeader();

            assertNotNull(bodyProtectedHeader);
            assertFalse(bodyProtectedHeader.isEmpty());
            assertNull(signerProtectedHeader);

            assertNotNull(bodyUnprotectedHeader);
            if (signature.isKeyBindingSignature()) {
                assertTrue(bodyUnprotectedHeader.isEmpty());
            } else {
                assertFalse(bodyUnprotectedHeader.isEmpty());
            }
            assertNull(signerUnprotectedHeader);

            Set<CBORObject> keySet = bodyProtectedHeader.getKeys();
            assertTrue(Utils.isCollectionNotEmpty(keySet));
            for (CBORObject signedPropertyKey : keySet) {
                assertTrue(CBORUtils.getSupportedProtectedCriticalHeaders().contains(signedPropertyKey));
            }

            CBORObject crit = bodyProtectedHeader.getHeader(COSEHeaderParameter.CRIT.cbor());
            if (crit != null) {
                assertTrue(crit.isArray());
                assertInstanceOf(CBORArray.class, crit);

                CBORArray critArray = (CBORArray) crit;
                assertFalse(critArray.isEmpty());
                for (CBORObject critItem : critArray.getValueAsList()) {
                    assertTrue(critItem.isUnsignedInteger() || critItem.isNegativeInteger());
                    assertInstanceOf(CBORSimpleObject.class, critItem);

                    Long labelId = critItem.getValueAsLong();
                    assertNotNull(labelId);

                    assertTrue(CBORUtils.getSupportedProtectedCriticalHeaders().contains(critItem));
                    assertTrue(CBORUtils.isRequiredCriticalHeader(critItem));
                }
            }

        }
    }

    @Override
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        super.checkAttestationDigestMatchers(diagnosticData);

        for (AttestationWrapper attestation : diagnosticData.getAttestations()) {
            for (XmlDigestMatcher xmlDigestMatcher : attestation.getDigestMatchers()) {
                if (DigestMatcherType.SELECTIVE_DISCLOSURE == xmlDigestMatcher.getType()) {
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim());
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim().getName());
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim().getValue());
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim().getNamespace());
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim().getId());
                }
            }
        }
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        for (AttestationWrapper attestation : diagnosticData.getAttestations()) {

            assertNotNull(attestation.getVersion());
            assertNotNull(attestation.getAttestationDocumentType());
            assertNotNull(attestation.getDigestAlgorithm());
            assertNotNull(attestation.getDevicePublicKey());
            assertNotNull(attestation.getIssuedAt());
            assertNotNull(attestation.getNotBefore());
            assertNotNull(attestation.getExpiration());

            if (Utils.isStringNotEmpty(getPayloadParameters().selectivelyDisclosable().getDocumentType())) {
                assertEquals(getPayloadParameters().selectivelyDisclosable().getDocumentType(), attestation.getClaimedDocumentType());
            } else {
                assertNull(attestation.getClaimedDocumentType());
            }

            assertEquals(getPayloadParameters().getVersion(), attestation.getVersion());
            assertEquals(getPayloadParameters().getDocType(), attestation.getAttestationDocumentType());
            assertTrue(attestation.getDigestMatchers().stream().allMatch(m -> getPayloadParameters().getDigestAlgorithm() == m.getDigestMethod()));
            assertArrayEquals(getPayloadParameters().getDeviceKey().getEncoded(), attestation.getDevicePublicKey());
            if (Utils.isCollectionNotEmpty(getPayloadParameters().getKeyAuthorizationsNamespaces())) {
                assertEquals(getPayloadParameters().getKeyAuthorizationsNamespaces(), attestation.getDeviceKeyAuthorizedNamespaces());
            } else {
                assertFalse(Utils.isCollectionNotEmpty(attestation.getDeviceKeyAuthorizedNamespaces()));
            }
            if (Utils.isMapNotEmpty(getPayloadParameters().getKeyAuthorizationsDataElements())) {
                assertEquals(getPayloadParameters().getKeyAuthorizationsDataElements(), attestation.getDeviceKeyAuthorizedDataElements());
            } else {
                assertFalse(Utils.isMapNotEmpty(attestation.getDeviceKeyAuthorizedDataElements()));
            }
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getSigned()), DSSUtils.formatDateToRFC(attestation.getIssuedAt()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getValidFrom()), DSSUtils.formatDateToRFC(attestation.getNotBefore()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getValidUntil()), DSSUtils.formatDateToRFC(attestation.getExpiration()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getExpectedUpdate()), DSSUtils.formatDateToRFC(attestation.getNextUpdate()));

            assertStatusListEqual(getPayloadParameters().getStatusList(), attestation);
            assertIdentifierListEqual(getPayloadParameters().getIdentifierList(), attestation);

            assertEquals(getPayloadParameters().getCategory(), attestation.getCategory());
            assertEquals(Utils.isTrue(getPayloadParameters().isShortLived()), Utils.isTrue(attestation.getShortLived()));
            assertEquals(Utils.isTrue(getPayloadParameters().isOneTime()), Utils.isTrue(attestation.getOneTimeUse()));

            assertEquals(getPayloadParameters().selectivelyDisclosable().getGivenName(), attestation.getGivenName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getFamilyName(), attestation.getFamilyName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getEmail(), attestation.getEmail());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getSex(), attestation.getGender());
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().selectivelyDisclosable().getBirthdate()), DSSUtils.formatDateToRFC(attestation.getBirthdate()));
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPhoneNumber(), attestation.getPhoneNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirth(), attestation.getPlaceOfBirth());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirthCountry(), attestation.getPlaceOfBirthCountry());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirthLocality(), attestation.getPlaceOfBirthCity());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirthRegion(), attestation.getPlaceOfBirthRegion());
            if (Utils.isStringNotEmpty(getPayloadParameters().selectivelyDisclosable().getNationality())) {
                assertTrue(Utils.isCollectionNotEmpty(attestation.getNationalities()));
                assertEquals(getPayloadParameters().selectivelyDisclosable().getNationality(), attestation.getNationalities().get(0));
            } else if (Utils.isCollectionNotEmpty(getPayloadParameters().selectivelyDisclosable().getNationalities())) {
                assertTrue(Utils.isCollectionNotEmpty(attestation.getNationalities()));
                assertEquals(getPayloadParameters().selectivelyDisclosable().getNationalities(), attestation.getNationalities());
            } else {
                assertFalse(Utils.isCollectionNotEmpty(attestation.getNationalities()));
            }
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBirthGivenName(), attestation.getBirthGivenName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBirthFamilyName(), attestation.getBirthFamilyName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getTitle(), attestation.getTitle());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getMobilePhoneNumber(), attestation.getMobilePhoneNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPseudonym(), attestation.getPseudonym());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingCountry(), attestation.getDocumentIssuingAuthorityCountry());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingAuthority(), attestation.getDocumentIssuingAuthority());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getDocumentNumber(), attestation.getDocumentNumber());
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getPortrait(), attestation.getPortrait());
            assertDrivingPrivilegesEquals(getPayloadParameters().selectivelyDisclosable().getDrivingPrivileges(), attestation.getDrivingPrivileges());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getDistinguishingSign(), attestation.getDocumentIssuingAuthorityCountryUNDistinguishingSign());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPersonalAdministrativeNumber(), attestation.getPersonalAdministrativeNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getHeight(), attestation.getHeight());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getWeight(), attestation.getWeight());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getEyeColour(), attestation.getEyeColour());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getHairColour(), attestation.getHairColour());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPostalAddress(), attestation.getResidentPostalAddress());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPortraitCaptureDate(), attestation.getPortraitCaptureDate());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAgeInYears(), attestation.getAgeInYears());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAgeBirthYear(), attestation.getAgeBirthYear());
            if (Utils.isMapNotEmpty(getPayloadParameters().selectivelyDisclosable().getAgeOverNN())) {
                for (Map.Entry<Integer, Boolean> ageEntry : getPayloadParameters().selectivelyDisclosable().getAgeOverNN().entrySet()) {
                    assertEquals(ageEntry.getValue(), attestation.isAgeOver(ageEntry.getKey()));
                }
            }
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingJurisdiction(), attestation.getDocumentIssuingAuthorityJurisdiction());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressCity(), attestation.getResidentAddressCity());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressState(), attestation.getResidentAddressState());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressPostalCode(), attestation.getResidentAddressPostalCode());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressCountry(), attestation.getResidentAddressCountry());
            if (Utils.isMapNotEmpty(getPayloadParameters().selectivelyDisclosable().getBiometricTemplate())) {
                for (Map.Entry<String, byte[]> bioEntry : getPayloadParameters().selectivelyDisclosable().getBiometricTemplate().entrySet()) {
                    assertArrayEquals(bioEntry.getValue(), attestation.getBiometricTemplate(bioEntry.getKey()));
                }
            }
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getBiometricTemplateFace(), attestation.getBiometricTemplate("face"));
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getSignatureUsualMark(), attestation.getSignatureUsualMark());
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getFingerprint(), attestation.getFingerprint());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBusinessName(), attestation.getBusinessName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getOrganizationName(), attestation.getOrganizationName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBirthFullName(), attestation.getBirthFullName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getProfession(), attestation.getProfession());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipFather(), attestation.getRelationshipFather());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipMother(), attestation.getRelationshipMother());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipParent(), attestation.getRelationshipParent());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSon(), attestation.getRelationshipSon());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipDaughter(), attestation.getRelationshipDaughter());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipBrother(), attestation.getRelationshipBrother());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSister(), attestation.getRelationshipSister());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSibling(), attestation.getRelationshipSibling());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSpouse(), attestation.getRelationshipSpouse());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipFatherInLaw(), attestation.getRelationshipFatherInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipMotherInLaw(), attestation.getRelationshipMotherInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipParentInLaw(), attestation.getRelationshipParentInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSonInLaw(), attestation.getRelationshipSonInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipDaughterInLaw(), attestation.getRelationshipDaughterInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipChildInLaw(), attestation.getRelationshipChildInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipParentalAuthority(), attestation.getRelationshipParentalAuthority());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipLegalRepresentative(), attestation.getRelationshipLegalRepresentative());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipAgent(), attestation.getRelationshipAgent());
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().selectivelyDisclosable().getAdministrativeIssuanceDate()), DSSUtils.formatDateToRFC(attestation.getAdministrativeIssuanceDate()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().selectivelyDisclosable().getAdministrativeExpirationDate()), DSSUtils.formatDateToRFC(attestation.getAdministrativeExpirationDate()));
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressStreet(), attestation.getResidentAddressStreet());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressHouseNumber(), attestation.getResidentAddressHouseNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getTrustAnchor(), attestation.getTrustAnchor());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingAuthorityRegistrationIdentifier(), attestation.getIssuingRegistrationIdentifier());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectGivenName(), attestation.getAttestedAttributesSubjectGivenName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectFamilyName(), attestation.getAttestedAttributesSubjectFamilyName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectPseudonym(), attestation.getAttestedAttributesSubjectPseudonym());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectDocumentNumber(), attestation.getAttestedAttributesSubjectDocumentNumber());
        }
    }

    protected void assertDrivingPrivilegesEquals(List<MdocDrivingPrivilege> drivingPrivileges, DrivingPrivilegesClaimWrapper drivingPrivilegesClaimWrapper) {
        if (Utils.isCollectionNotEmpty(drivingPrivileges)) {
            assertNotNull(drivingPrivilegesClaimWrapper);
            assertEquals(drivingPrivileges.size(), drivingPrivilegesClaimWrapper.getDrivingPrivileges().size());
            for (int i = 0; i < drivingPrivileges.size(); i++) {
                MdocDrivingPrivilege mdocDrivingPrivilege = drivingPrivileges.get(i);
                DrivingPrivilegeClaimWrapper drivingPrivilegeClaimWrapper = drivingPrivilegesClaimWrapper.getDrivingPrivileges().get(i);
                assertEquals(mdocDrivingPrivilege.getVehicleCategoryCode(), drivingPrivilegeClaimWrapper.getVehicleCategoryCode().getText());
                if (mdocDrivingPrivilege.getIssueDate() != null) {
                    assertNotNull(drivingPrivilegeClaimWrapper.getIssueDate());
                    assertEquals(mdocDrivingPrivilege.getIssueDate(), drivingPrivilegeClaimWrapper.getIssueDate().getDateTime());
                } else {
                    assertNull(drivingPrivilegeClaimWrapper.getIssueDate());
                }
                if (mdocDrivingPrivilege.getExpiryDate() != null) {
                    assertNotNull(drivingPrivilegeClaimWrapper.getExpiryDate());
                    assertEquals(mdocDrivingPrivilege.getExpiryDate(), drivingPrivilegeClaimWrapper.getExpiryDate().getDateTime());
                } else {
                    assertNull(drivingPrivilegeClaimWrapper.getExpiryDate());
                }
                if (Utils.isCollectionNotEmpty(mdocDrivingPrivilege.getCodes())) {
                    assertNotNull(drivingPrivilegeClaimWrapper.getCodes());
                    for (int j = 0; j < mdocDrivingPrivilege.getCodes().size(); j++) {
                        MdocDrivingPrivilege.Code code = mdocDrivingPrivilege.getCodes().get(j);
                        DrivingPrivilegeCodeClaimWrapper codeWrapper = drivingPrivilegeClaimWrapper.getCodes().getCodes().get(j);
                        assertEquals(code.getCode(), codeWrapper.getCode().getText());
                        if (Utils.isStringNotEmpty(code.getSign())) {
                            assertNotNull(codeWrapper.getSign());
                            assertEquals(code.getSign(), codeWrapper.getSign().getText());
                        } else {
                            assertNull(codeWrapper.getSign());
                        }
                        if (Utils.isStringNotEmpty(code.getValue())) {
                            assertNotNull(codeWrapper.getValue());
                            assertEquals(code.getValue(), codeWrapper.getValue().getText());
                        } else {
                            assertNull(codeWrapper.getValue());
                        }
                    }

                } else {
                    assertNull(drivingPrivilegeClaimWrapper.getCodes());
                }

            }

        } else {
            assertNull(drivingPrivilegesClaimWrapper);
        }
    }

    private void assertStatusListEqual(TokenStatusList statusList, AttestationWrapper attestation) {
        if (statusList != null) {
            assertEquals(statusList.getIndex(), attestation.getStatusIndex());
            assertEquals(statusList.getUri(), attestation.getStatusUri());
            if (statusList.getCertificate() != null) {
                assertArrayEquals(statusList.getCertificate().getEncoded(), attestation.getStatusCertificate());
            } else {
                assertNull(attestation.getStatusCertificate());
            }
        } else {
            assertNull(attestation.getStatusIndex());
            assertNull(attestation.getStatusUri());
            assertNull(attestation.getStatusCertificate());
        }
    }

    private void assertIdentifierListEqual(MdocIdentifierList identifierList, AttestationWrapper attestation) {
        if (identifierList != null) {
            assertArrayEquals(identifierList.getIdentifier(), attestation.getIdentifierListId());
            assertEquals(identifierList.getUri(), attestation.getIdentifierListUri());
            if (identifierList.getCertificate() != null) {
                assertArrayEquals(identifierList.getCertificate().getEncoded(), attestation.getIdentifierListCertificate());
            } else {
                assertNull(attestation.getIdentifierListCertificate());
            }
        } else {
            assertNull(attestation.getIdentifierListId());
            assertNull(attestation.getIdentifierListUri());
            assertNull(attestation.getIdentifierListCertificate());
        }
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        super.checkStructureValidation(diagnosticData);

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            COSESignatureType coseSignatureType = signature.getCOSESignatureType();
            assertNotNull(coseSignatureType);
            assertEquals(COSESignatureType.COSE_SIGN1, coseSignatureType);
            assertFalse(signature.isCOSETagged());
            assertFalse(signature.isCounterSignature());
        }
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertTrue(signatureWrapper.isSigningCertificateIdentified());
            assertTrue(signatureWrapper.isSigningCertificateReferencePresent());

            CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
            assertNotNull(signingCertificateReference);
            assertTrue(signingCertificateReference.isDigestValuePresent());
            assertTrue(signingCertificateReference.isDigestValueMatch());
            if (signingCertificateReference.isIssuerSerialPresent()) {
                assertTrue(signingCertificateReference.isIssuerSerialMatch());
            }

            CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
            assertNotNull(signingCertificate);
            String signingCertificateId = signingCertificate.getId();
            String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
            String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
            assertEquals(signingCertificate.getCertificateDN(), certificateDN);
            assertEquals(signingCertificate.getSerialNumber(), certificateSerialNumber);

            assertTrue(Utils.isCollectionEmpty(signatureWrapper.foundCertificates()
                    .getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE)));

            FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
            List<RelatedCertificateWrapper> signingCertificates = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);

            CBAdESSignatureParameters signatureParameters = signatureWrapper.isKeyBindingSignature() ? getKeyBindingSignatureParameters() : getSignatureParameters();
            if (signatureParameters.isIncludeCertificateChainThumbprints()) {
                BaselineBCertificateSelector certificateSelector = new BaselineBCertificateSelector(
                        signatureParameters.getSigningCertificate(), signatureParameters.getCertificateChain())
                        .setTrustAnchorBPPolicy(signatureParameters.bLevel().isTrustAnchorBPPolicy())
                        .setTrustedCertificateSource(getTrustedCertificateSource());
                assertEquals(certificateSelector.getCertificates().size(), signingCertificates.size());
            } else {
                assertEquals(1, signingCertificates.size());
            }

            List<CertificateRefWrapper> signingCertificateRefs = null;
            for (RelatedCertificateWrapper certificateWrapper : signingCertificates) {
                if (signatureWrapper.getSigningCertificate().getId().equals(certificateWrapper.getId())) {
                    signingCertificateRefs = certificateWrapper.getReferences();
                    break;
                }
            }
            assertNotNull(signingCertificateRefs);

            List<RelatedCertificateWrapper> kidCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER);
            List<RelatedCertificateWrapper> x5uCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.X509_URL);

            int signCertRefs = 1 + (Utils.isCollectionNotEmpty(kidCerts) ? 1 : 0) + (Utils.isCollectionNotEmpty(x5uCerts) ? 1 : 0);
            assertEquals(signCertRefs, signingCertificateRefs.size());

            if (signatureParameters.isIncludeKeyIdentifier()) {
                assertEquals(1, kidCerts.size());
            } else if (Utils.isStringNotEmpty(signatureParameters.getX509Url())) {
                assertTrue(Utils.isCollectionNotEmpty(x5uCerts));
            } else {
                assertEquals(0, kidCerts.size());
                assertEquals(0, x5uCerts.size());
            }

            for (CertificateRefWrapper certificateRef : signingCertificateRefs) {
                if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRef.getOrigin())) {
                    assertNotNull(certificateRef.getDigestAlgoAndValue());
                    assertNotNull(certificateRef.getDigestMethod());
                    assertTrue(certificateRef.isDigestValuePresent());
                    assertTrue(certificateRef.isDigestValueMatch());
                    assertNull(certificateRef.getIssuerSerial());

                } else if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRef.getOrigin())) {
                    assertNotNull(certificateRef.getCertificateId());
                    if (certificateRef.getIssuerSerial() != null) {
                        assertNotNull(certificateRef.getIssuerSerial());
                        assertTrue(certificateRef.isIssuerSerialPresent());
                        assertTrue(certificateRef.isIssuerSerialMatch());
                    } else {
                        assertNotNull(certificateRef.getKid());
                    }
                    assertNull(certificateRef.getDigestAlgoAndValue());

                } else if (CertificateRefOrigin.X509_URL.equals(certificateRef.getOrigin())) {
                    assertNotNull(certificateRef.getCertificateId());
                    assertNotNull(certificateRef.getX509Url());
                }
            }
        }
    }

    @Override
    protected void checkCertificates(DiagnosticData diagnosticData) {
        super.checkCertificates(diagnosticData);

        for (AttestationWrapper attestationWrapper : diagnosticData.getAttestations()) {
            for (SignatureWrapper signature : attestationWrapper.getAttestationSignatures()) {
                assertFalse(signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.UNPROTECTED_HEADER).isEmpty());
            }
        }
    }

    protected DSSDocument buildSessionTranscript() {
        byte[] select = new byte[]{0x01, 0x02};
        byte[] request = new byte[]{0x03, 0x04};
        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcHandover(select, request)
                        .security(EllipticCurve.P_256, getSigningCert().getPublicKey())
                        .eReaderKey(getSigningCert().getPublicKey());

        return builder.build();
    }

}
