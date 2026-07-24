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
package eu.europa.esig.dss.eaa.mdoc.creation;

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
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegeClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegeCodeClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegesClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.eaa.common.creation.TokenStatusList;
import eu.europa.esig.dss.eaa.common.validation.AbstractAttestationPresentationTestIssuance;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDrivingPrivilege;
import eu.europa.esig.dss.eaa.mdoc.validation.MdocDeviceResponseAttestationDocumentValidator;
import eu.europa.esig.dss.eaa.mdoc.validation.MdocValidationParameters;
import eu.europa.esig.dss.enumerations.AttestationFormat;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.AttestationPresentationType;
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

public abstract class AbstractMdocPresentationTestIssuance extends AbstractAttestationPresentationTestIssuance
        <CBAdESSignatureParameters, MdocPayloadParameters, MdocClaim, MdocSelectiveDisclosure, MdocKeyBindingParameters> {

    @Override
    protected MdocService getService() {
        return new MdocService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument issuePresentation(DSSDocument signedEAA, List<MdocSelectiveDisclosure> disclosures, DSSDocument keyBindingSignature) {
        if (includeKeyBindingSignature()) {
            return getService().issuePresentation(signedEAA, disclosures, keyBindingSignature, getKeyBindingParameters());
        } else {
            return getService().createIssuerSigned(signedEAA, disclosures);
        }
    }

    @Override
    protected MimeType getExpectedMime() {
        return MimeTypeEnum.CBOR;
    }

    @Override
    protected AttestationFormat getEAAType() {
        return AttestationFormat.ISO_IEC_MDOC;
    }

    @Override
    protected AttestationPresentationType getEAAPresentationType() {
        if (keyBindingPresent()) {
            return AttestationPresentationType.MDOC_DEVICE_RESPONSE;
        } else {
            return AttestationPresentationType.MDOC_ISSUER_SIGNED;
        }
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        if (keyBindingPresent()) {
            MdocDeviceResponseAttestationDocumentValidator mdocValidator = assertInstanceOf(MdocDeviceResponseAttestationDocumentValidator.class, validator);
            MdocValidationParameters mdocValidationParameters = new MdocValidationParameters();
            mdocValidationParameters.setSessionTranscript(buildSessionTranscript());
            mdocValidator.setEAAValidationParameters(mdocValidationParameters);
        }
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
    protected void checkEAADigestMatchers(DiagnosticData diagnosticData) {
        super.checkEAADigestMatchers(diagnosticData);

        for (AttestationWrapper eaa : diagnosticData.getEAAs()) {
            for (XmlDigestMatcher xmlDigestMatcher : eaa.getDigestMatchers()) {
                if (DigestMatcherType.EAA_DISCLOSURE == xmlDigestMatcher.getType()) {
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

        for (AttestationWrapper eaa : diagnosticData.getEAAs()) {

            assertNotNull(eaa.getVersion());
            assertNotNull(eaa.getAttestationDocumentType());
            assertNotNull(eaa.getDigestAlgorithm());
            assertNotNull(eaa.getDevicePublicKey());
            assertNotNull(eaa.getIssuedAt());
            assertNotNull(eaa.getNotBefore());
            assertNotNull(eaa.getExpiration());

            if (Utils.isStringNotEmpty(getPayloadParameters().selectivelyDisclosable().getDocumentType())) {
                assertEquals(getPayloadParameters().selectivelyDisclosable().getDocumentType(), eaa.getClaimedDocumentType());
            } else {
                assertNull(eaa.getClaimedDocumentType());
            }

            assertEquals(getPayloadParameters().getVersion(), eaa.getVersion());
            assertEquals(getPayloadParameters().getDocType(), eaa.getAttestationDocumentType());
            assertTrue(eaa.getDigestMatchers().stream().allMatch(m -> getPayloadParameters().getDigestAlgorithm() == m.getDigestMethod()));
            assertArrayEquals(getPayloadParameters().getDeviceKey().getEncoded(), eaa.getDevicePublicKey());
            if (Utils.isCollectionNotEmpty(getPayloadParameters().getKeyAuthorizationsNamespaces())) {
                assertEquals(getPayloadParameters().getKeyAuthorizationsNamespaces(), eaa.getDeviceKeyAuthorizedNamespaces());
            } else {
                assertFalse(Utils.isCollectionNotEmpty(eaa.getDeviceKeyAuthorizedNamespaces()));
            }
            if (Utils.isMapNotEmpty(getPayloadParameters().getKeyAuthorizationsDataElements())) {
                assertEquals(getPayloadParameters().getKeyAuthorizationsDataElements(), eaa.getDeviceKeyAuthorizedDataElements());
            } else {
                assertFalse(Utils.isMapNotEmpty(eaa.getDeviceKeyAuthorizedDataElements()));
            }
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getSigned()), DSSUtils.formatDateToRFC(eaa.getIssuedAt()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getValidFrom()), DSSUtils.formatDateToRFC(eaa.getNotBefore()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getValidUntil()), DSSUtils.formatDateToRFC(eaa.getExpiration()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getExpectedUpdate()), DSSUtils.formatDateToRFC(eaa.getNextUpdate()));

            assertStatusListEqual(getPayloadParameters().getStatusList(), eaa);
            assertIdentifierListEqual(getPayloadParameters().getIdentifierList(), eaa);

            assertEquals(getPayloadParameters().getCategory(), eaa.getCategory());
            assertEquals(Utils.isTrue(getPayloadParameters().isShortLived()), Utils.isTrue(eaa.getShortLived()));
            assertEquals(Utils.isTrue(getPayloadParameters().isOneTime()), Utils.isTrue(eaa.getOneTimeUse()));

            assertEquals(getPayloadParameters().selectivelyDisclosable().getGivenName(), eaa.getGivenName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getFamilyName(), eaa.getFamilyName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getEmail(), eaa.getEmail());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getSex(), eaa.getGender());
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().selectivelyDisclosable().getBirthdate()), DSSUtils.formatDateToRFC(eaa.getBirthdate()));
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPhoneNumber(), eaa.getPhoneNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirth(), eaa.getPlaceOfBirth());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirthCountry(), eaa.getPlaceOfBirthCountry());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirthLocality(), eaa.getPlaceOfBirthCity());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirthRegion(), eaa.getPlaceOfBirthRegion());
            if (Utils.isStringNotEmpty(getPayloadParameters().selectivelyDisclosable().getNationality())) {
                assertTrue(Utils.isCollectionNotEmpty(eaa.getNationalities()));
                assertEquals(getPayloadParameters().selectivelyDisclosable().getNationality(), eaa.getNationalities().get(0));
            } else if (Utils.isCollectionNotEmpty(getPayloadParameters().selectivelyDisclosable().getNationalities())) {
                assertTrue(Utils.isCollectionNotEmpty(eaa.getNationalities()));
                assertEquals(getPayloadParameters().selectivelyDisclosable().getNationalities(), eaa.getNationalities());
            } else {
                assertFalse(Utils.isCollectionNotEmpty(eaa.getNationalities()));
            }
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBirthGivenName(), eaa.getBirthGivenName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBirthFamilyName(), eaa.getBirthFamilyName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getTitle(), eaa.getTitle());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getMobilePhoneNumber(), eaa.getMobilePhoneNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPseudonym(), eaa.getPseudonym());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingCountry(), eaa.getDocumentIssuingAuthorityCountry());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingAuthority(), eaa.getDocumentIssuingAuthority());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getDocumentNumber(), eaa.getDocumentNumber());
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getPortrait(), eaa.getPortrait());
            assertDrivingPrivilegesEquals(getPayloadParameters().selectivelyDisclosable().getDrivingPrivileges(), eaa.getDrivingPrivileges());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getDistinguishingSign(), eaa.getDocumentIssuingAuthorityCountryUNDistinguishingSign());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPersonalAdministrativeNumber(), eaa.getPersonalAdministrativeNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getHeight(), eaa.getHeight());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getWeight(), eaa.getWeight());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getEyeColour(), eaa.getEyeColour());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getHairColour(), eaa.getHairColour());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPostalAddress(), eaa.getResidentPostalAddress());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPortraitCaptureDate(), eaa.getPortraitCaptureDate());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAgeInYears(), eaa.getAgeInYears());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAgeBirthYear(), eaa.getAgeBirthYear());
            if (Utils.isMapNotEmpty(getPayloadParameters().selectivelyDisclosable().getAgeOverNN())) {
                for (Map.Entry<Integer, Boolean> ageEntry : getPayloadParameters().selectivelyDisclosable().getAgeOverNN().entrySet()) {
                    assertEquals(ageEntry.getValue(), eaa.isAgeOver(ageEntry.getKey()));
                }
            }
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingJurisdiction(), eaa.getDocumentIssuingAuthorityJurisdiction());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressCity(), eaa.getResidentAddressCity());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressState(), eaa.getResidentAddressState());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressPostalCode(), eaa.getResidentAddressPostalCode());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressCountry(), eaa.getResidentAddressCountry());
            if (Utils.isMapNotEmpty(getPayloadParameters().selectivelyDisclosable().getBiometricTemplate())) {
                for (Map.Entry<String, byte[]> bioEntry : getPayloadParameters().selectivelyDisclosable().getBiometricTemplate().entrySet()) {
                    assertArrayEquals(bioEntry.getValue(), eaa.getBiometricTemplate(bioEntry.getKey()));
                }
            }
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getBiometricTemplateFace(), eaa.getBiometricTemplate("face"));
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getSignatureUsualMark(), eaa.getSignatureUsualMark());
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getFingerprint(), eaa.getFingerprint());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBusinessName(), eaa.getBusinessName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getOrganizationName(), eaa.getOrganizationName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBirthFullName(), eaa.getBirthFullName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getProfession(), eaa.getProfession());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipFather(), eaa.getRelationshipFather());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipMother(), eaa.getRelationshipMother());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipParent(), eaa.getRelationshipParent());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSon(), eaa.getRelationshipSon());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipDaughter(), eaa.getRelationshipDaughter());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipBrother(), eaa.getRelationshipBrother());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSister(), eaa.getRelationshipSister());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSibling(), eaa.getRelationshipSibling());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSpouse(), eaa.getRelationshipSpouse());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipFatherInLaw(), eaa.getRelationshipFatherInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipMotherInLaw(), eaa.getRelationshipMotherInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipParentInLaw(), eaa.getRelationshipParentInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSonInLaw(), eaa.getRelationshipSonInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipDaughterInLaw(), eaa.getRelationshipDaughterInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipChildInLaw(), eaa.getRelationshipChildInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipParentalAuthority(), eaa.getRelationshipParentalAuthority());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipLegalRepresentative(), eaa.getRelationshipLegalRepresentative());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipAgent(), eaa.getRelationshipAgent());
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().selectivelyDisclosable().getAdministrativeIssuanceDate()), DSSUtils.formatDateToRFC(eaa.getAdministrativeIssuanceDate()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().selectivelyDisclosable().getAdministrativeExpirationDate()), DSSUtils.formatDateToRFC(eaa.getAdministrativeExpirationDate()));
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressStreet(), eaa.getResidentAddressStreet());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressHouseNumber(), eaa.getResidentAddressHouseNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getTrustAnchor(), eaa.getTrustAnchor());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingAuthorityRegistrationIdentifier(), eaa.getIssuingRegistrationIdentifier());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectGivenName(), eaa.getAttestedAttributesSubjectGivenName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectFamilyName(), eaa.getAttestedAttributesSubjectFamilyName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectPseudonym(), eaa.getAttestedAttributesSubjectPseudonym());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectDocumentNumber(), eaa.getAttestedAttributesSubjectDocumentNumber());
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

    private void assertStatusListEqual(TokenStatusList statusList, AttestationWrapper eaa) {
        if (statusList != null) {
            assertEquals(statusList.getIndex(), eaa.getStatusIndex());
            assertEquals(statusList.getUri(), eaa.getStatusUri());
            if (statusList.getCertificate() != null) {
                assertArrayEquals(statusList.getCertificate().getEncoded(), eaa.getStatusCertificate());
            } else {
                assertNull(eaa.getStatusCertificate());
            }
        } else {
            assertNull(eaa.getStatusIndex());
            assertNull(eaa.getStatusUri());
            assertNull(eaa.getStatusCertificate());
        }
    }

    private void assertIdentifierListEqual(MdocIdentifierList identifierList, AttestationWrapper eaa) {
        if (identifierList != null) {
            assertArrayEquals(identifierList.getIdentifier(), eaa.getIdentifierListId());
            assertEquals(identifierList.getUri(), eaa.getIdentifierListUri());
            if (identifierList.getCertificate() != null) {
                assertArrayEquals(identifierList.getCertificate().getEncoded(), eaa.getIdentifierListCertificate());
            } else {
                assertNull(eaa.getIdentifierListCertificate());
            }
        } else {
            assertNull(eaa.getIdentifierListId());
            assertNull(eaa.getIdentifierListUri());
            assertNull(eaa.getIdentifierListCertificate());
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

        for (AttestationWrapper attestationWrapper : diagnosticData.getEAAs()) {
            for (SignatureWrapper signature : attestationWrapper.getEAASignatures()) {
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
