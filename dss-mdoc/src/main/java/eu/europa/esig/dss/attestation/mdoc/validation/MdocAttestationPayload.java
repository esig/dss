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
package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.attestation.mdoc.ETSI194721Headers;
import eu.europa.esig.dss.attestation.mdoc.EUDIPIDHeaders;
import eu.europa.esig.dss.attestation.mdoc.ISO180135Headers;
import eu.europa.esig.dss.attestation.mdoc.ISO232202Headers;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimBiometricTemplateXX;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimAgeOverNN;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimAttestedAttributesSubject;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimBirthDate;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimDeviceKeyInfo;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimDrivingPrivileges;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimMap;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimPlaceOfBirth;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimStatus;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimValidityInfo;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAddress;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAgeOverNN;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAgeEqualOrOver;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimArray;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAttestedAttributesSubject;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimBiometricTemplateXX;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimBoolean;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimByteString;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimCredentialSubject;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDate;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDeviceKey;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDrivingPrivileges;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimIntegrity;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimStatus;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimValidityInfo;
import eu.europa.esig.dss.spi.attestation.AttestationPayload;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Mdoc's representation of an attestation payload
 *
 */
public class MdocAttestationPayload extends MdocVerifiedClaimMap implements AttestationPayload {

    private static final long serialVersionUID = -5947789662835061427L;

    private static final Logger LOG = LoggerFactory.getLogger(MdocAttestationPayload.class);

    /**
     * Default constructor
     *
     * @param verifiedPayloadMap {@link VerifiedClaimMap}
     * @param docType {@link String}
     */
    public MdocAttestationPayload(final VerifiedClaimMap verifiedPayloadMap, final String docType) {
        super(verifiedPayloadMap.getMapValue());
    }

    @Override
    public VerifiedClaimString getIdentifier() {
        // not applicable
        return null;
    }

    @Override
    public VerifiedClaimString getIssuer() {
        // not applicable
        return null;
    }

    @Override
    public VerifiedClaimString getSubject() {
        // not applicable
        return null;
    }

    @Override
    public VerifiedClaimArray getAudience() {
        // not applicable
        return null;
    }

    @Override
    public VerifiedClaimDate getIssuedAtTime() {
        // see ValidityInfo
        return null;
    }

    @Override
    public VerifiedClaimDate getNotBeforeTime() {
        // see ValidityInfo
        return null;
    }

    @Override
    public VerifiedClaimDate getExpirationTime() {
        // see ValidityInfo
        return null;
    }

    @Override
    public VerifiedClaimDate getUpdatedAtTime() {
        // see ValidityInfo
        return null;
    }

    @Override
    public VerifiedClaimDeviceKey getDeviceKey() {
        VerifiedClaimMap deviceKeyInfo = getAsMap(forIso180135Implicit(MdocConstants.DEVICE_KEY_INFO), forIso232202Implicit(MdocConstants.DEVICE_KEY_INFO));
        if (deviceKeyInfo != null) {
            return new MdocVerifiedClaimDeviceKeyInfo(deviceKeyInfo);
        }
        return null;
    }

    @Override
    public VerifiedClaimString getCategory() {
        return getAsString(forEtsi194721(ETSI194721Headers.CATEGORY), forEUDIPid(EUDIPIDHeaders.ATTESTATION_LEGAL_CATEGORY));
    }

    @Override
    public VerifiedClaimString getVerifiableCredentialsType() {
        return null;
    }

    @Override
    public VerifiedClaimIntegrity getVerifiableCredentialsTypeIntegrity() {
        return null;
    }

    @Override
    public VerifiedClaimStatus getStatus() {
        VerifiedClaimMap statusClaim = getAsMap(MdocConstants.STATUS);
        if (statusClaim == null) {
            // Can be defined with a Long key
            Object statusClaimObject = value.get(MdocConstants.STATUS_LONG);
            if (statusClaimObject != null) {
                VerifiedClaim claim = createClaim(MdocConstants.STATUS_LONG.getValueAsString(), statusClaimObject);
                if (claim != null && claim.isMapValueType()) {
                    statusClaim = (VerifiedClaimMap) claim;
                }
            }
        }
        if (statusClaim != null) {
            return new MdocVerifiedClaimStatus(statusClaim);
        }
        return null;
    }

    @Override
    public VerifiedClaimString getNonce() {
        return null;
    }

    @Override
    public VerifiedClaimString getFullName() {
        return getAsString(forIso232202(ISO232202Headers.FULL_NAME, ISO232202Headers.FULL_NAME_LATIN1));
    }

    @Override
    public VerifiedClaimString getGivenName() {
        return getAsString(
                forIso180135(ISO180135Headers.GIVEN_NAME, ISO180135Headers.GIVEN_NAME_NATIONAL_CHARACTER),
                forIso232202(ISO232202Headers.GIVEN_NAME, ISO232202Headers.GIVEN_NAME_UNICODE, ISO232202Headers.GIVEN_NAME_LATIN1),
                forEUDIPid(EUDIPIDHeaders.GIVEN_NAME)
        );
    }

    @Override
    public VerifiedClaimString getFamilyName() {
        return getAsString(
                forIso180135(ISO180135Headers.FAMILY_NAME, ISO180135Headers.FAMILY_NAME_NATIONAL_CHARACTER),
                forIso232202(ISO232202Headers.FAMILY_NAME, ISO232202Headers.FAMILY_NAME_UNICODE, ISO232202Headers.FAMILY_NAME_LATIN1),
                forEUDIPid(EUDIPIDHeaders.FAMILY_NAME)
        );
    }

    @Override
    public VerifiedClaimString getMiddleName() {
        return null;
    }

    @Override
    public VerifiedClaimString getNickname() {
        return null;
    }

    @Override
    public VerifiedClaimString getShortName() {
        return null;
    }

    @Override
    public VerifiedClaimString getProfileUrl() {
        return null;
    }

    @Override
    public VerifiedClaimString getPictureUrl() {
        return null;
    }

    @Override
    public VerifiedClaimString getWebsiteUrl() {
        return null;
    }

    @Override
    public VerifiedClaimString getEmail() {
        return getAsString(forIso232202(ISO232202Headers.EMAIL_ADDRESS), forEUDIPid(EUDIPIDHeaders.EMAIL_ADDRESS));
    }

    @Override
    public VerifiedClaimBoolean getEmailVerified() {
        return null;
    }

    @Override
    public VerifiedClaimNumber getGender() {
        return getAsNumber(forIso180135(ISO180135Headers.SEX), forIso232202(ISO232202Headers.SEX), forEUDIPid(EUDIPIDHeaders.SEX));
    }

    @Override
    public VerifiedClaim getBirthdate() {
        VerifiedClaimDate birthdate = getAsDate(forIso180135(ISO180135Headers.BIRTH_DATE), forEUDIPid(EUDIPIDHeaders.BIRTH_DATE));
        if (birthdate != null) {
            return birthdate;
        }
        VerifiedClaimMap birthdateMap = getAsMap(forIso232202(ISO232202Headers.BIRTH_DATE));
        if (birthdateMap != null) {
            return new MdocVerifiedClaimBirthDate(birthdateMap);
        }
        return null;
    }

    @Override
    public VerifiedClaimString getTimezone() {
        return null;
    }

    @Override
    public VerifiedClaimString getLocale() {
        return null;
    }

    @Override
    public VerifiedClaimAddress getAddress() {
        // see #getPostalAddress, #getResidentAddressCity, etc.
        return null;
    }

    @Override
    public VerifiedClaimString getPhoneNumber() {
        return getAsString(forIso232202(ISO232202Headers.TELEPHONE_NUMBER));
    }

    @Override
    public VerifiedClaimBoolean getPhoneNumberVerified() {
        return null;
    }

    @Override
    public VerifiedClaim getPlaceOfBirth() {
        VerifiedClaimString placeOfBirth = getAsString(forIso180135(ISO180135Headers.BIRTH_PLACE), forIso232202(ISO232202Headers.BIRTHPLACE));
        if (placeOfBirth != null) {
            return placeOfBirth;
        }
        VerifiedClaimMap placeOfBirthMap = getAsMap(forEUDIPid(EUDIPIDHeaders.PLACE_OF_BIRTH));
        if (placeOfBirthMap != null) {
            return new MdocVerifiedClaimPlaceOfBirth(placeOfBirthMap);
        }
        return null;
    }

    @Override
    public VerifiedClaim getNationalities() {
        VerifiedClaimString nationalities = getAsString(forIso180135(ISO180135Headers.NATIONALITY), forIso232202(ISO232202Headers.NATIONALITY));
        if (nationalities != null) {
            return nationalities;
        }
        return getAsArray(forEUDIPid(EUDIPIDHeaders.NATIONALITY));
    }

    @Override
    public VerifiedClaimString getBirthGivenName() {
        return getAsString(forEUDIPid(EUDIPIDHeaders.GIVEN_NAME_BIRTH));
    }

    @Override
    public VerifiedClaimString getBirthFamilyName() {
        return getAsString(forEUDIPid(EUDIPIDHeaders.FAMILY_NAME_BIRTH));
    }

    @Override
    public VerifiedClaimString getBirthMiddleName() {
        return null;
    }

    @Override
    public VerifiedClaimString getSalutation() {
        return null;
    }

    @Override
    public VerifiedClaimString getTitle() {
        return getAsString(forIso232202(ISO232202Headers.TITLE));
    }

    @Override
    public VerifiedClaimString getMobilePhoneNumber() {
        return getAsString(forEUDIPid(EUDIPIDHeaders.MOBILE_PHONE_NUMBER));
    }

    @Override
    public VerifiedClaimString getPseudonym() {
        return getAsString(forEtsi194721(ETSI194721Headers.ALSO_KNOWN_AS));
    }

    @Override
    public List<VerifiedClaimCredentialSubject> getCredentialSubjects() {
        return null;
    }

    @Override
    public VerifiedClaimString getIssuingCountry() {
        return getAsString(forIso180135(ISO180135Headers.ISSUING_COUNTRY), forIso232202(ISO232202Headers.ISSUING_COUNTRY),
                forEUDIPid(EUDIPIDHeaders.ISSUING_COUNTRY));
    }

    @Override
    public VerifiedClaimString getIssuingAuthority() {
        return getAsString(
                forIso180135(ISO180135Headers.ISSUING_AUTHORITY),
                forIso232202(ISO232202Headers.ISSUING_AUTHORITY, ISO232202Headers.ISSUING_AUTHORITY_UNICODE, ISO232202Headers.ISSUING_AUTHORITY_LATIN1),
                forEUDIPid(EUDIPIDHeaders.ISSUING_AUTHORITY)
        );
    }

    @Override
    public VerifiedClaimString getDocumentNumber() {
        return getAsString(forIso180135(ISO180135Headers.LICENCE_NUMBER), forIso232202(ISO232202Headers.DOCUMENT_NUMBER),
                forEUDIPid(EUDIPIDHeaders.DOCUMENT_NUMBER));
    }

    @Override
    public VerifiedClaimByteString getPortrait() {
        return getAsByteString(forIso180135(ISO180135Headers.PORTRAIT), forIso232202(ISO232202Headers.PORTRAIT), forEUDIPid(EUDIPIDHeaders.PORTRAIT));
    }

    @Override
    public VerifiedClaimDrivingPrivileges getDrivingPrivileges() {
        VerifiedClaimArray claimDrivingPrivileges = getAsArray(forIso180135(ISO180135Headers.DRIVING_PRIVILEGES));
        if (claimDrivingPrivileges != null) {
            return new MdocVerifiedClaimDrivingPrivileges(claimDrivingPrivileges);
        }
        return null;
    }

    @Override
    public VerifiedClaimString getUNDistinguishingSign() {
        return getAsString(forIso180135(ISO180135Headers.UN_DISTINGUISHING_SIGN));
    }

    @Override
    public VerifiedClaimString getPersonalAdministrativeNumber() {
        return getAsString(forIso180135(ISO180135Headers.ADMINISTRATIVE_NUMBER), forEUDIPid(EUDIPIDHeaders.PERSONAL_ADMINISTRATIVE_NUMBER));
    }

    @Override
    public VerifiedClaimNumber getHeight() {
        return getAsNumber(forIso180135(ISO180135Headers.HEIGHT), forIso232202(ISO232202Headers.HEIGHT));
    }

    @Override
    public VerifiedClaimNumber getWeight() {
        return getAsNumber(forIso180135(ISO180135Headers.WEIGHT), forIso232202(ISO232202Headers.WEIGHT));
    }

    @Override
    public VerifiedClaimString getEyeColour() {
        return getAsString(forIso180135(ISO180135Headers.EYE_COLOUR));
    }

    @Override
    public VerifiedClaimString getHairColour() {
        return getAsString(forIso180135(ISO180135Headers.HAIR_COLOUR));
    }

    @Override
    public VerifiedClaimString getPostalAddress() {
        return getAsString(
                forIso180135(ISO180135Headers.RESIDENT_ADDRESS),
                forIso232202(ISO232202Headers.RESIDENT_ADDRESS, ISO232202Headers.RESIDENT_ADDRESS_UNICODE, ISO232202Headers.RESIDENT_ADDRESS_LATIN1),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_ADDRESS)
        );
    }

    @Override
    public VerifiedClaimDate getPortraitCaptureDate() {
        return getAsDate(forIso180135(ISO180135Headers.PORTRAIT_CAPTURE_DATE), forIso232202(ISO232202Headers.PORTRAIT_CAPTURE_DATE));
    }

    @Override
    public VerifiedClaimNumber getAgeInYears() {
        return getAsNumber(forIso180135(ISO180135Headers.AGE_IN_YEARS), forIso232202(ISO232202Headers.AGE_IN_YEARS));
    }

    @Override
    public VerifiedClaimNumber getAgeBirthYear() {
        return getAsNumber(forIso180135(ISO180135Headers.AGE_BIRTH_YEAR), forIso232202(ISO232202Headers.AGE_BIRTH_YEAR));
    }

    @Override
    public VerifiedClaimAgeEqualOrOver getAgeEqualOrOver() {
        return null;
    }

    @Override
    public List<VerifiedClaimAgeOverNN> getAgeOverNN() {
        List<VerifiedClaim> ageOverNNClaims = getAllStartingWith(forIso180135(ISO180135Headers.AGE_OVER_NN), forIso232202(ISO232202Headers.AGE_OVER_NN));
        if (Utils.isCollectionEmpty(ageOverNNClaims)) {
            return Collections.emptyList();
        }
        final List<VerifiedClaimAgeOverNN> result = new ArrayList<>();
        for (VerifiedClaim claim : ageOverNNClaims) {
            if (claim.isBooleanValueType()) {
                result.add(new MdocVerifiedClaimAgeOverNN((VerifiedClaimBoolean) claim));
            } else {
                LOG.warn("Claim with name '{}' shall have a value of CBOR Boolean type!", claim.getName());
            }
        }
        return result;
    }

    @Override
    public VerifiedClaimString getIssuingJurisdiction() {
        return getAsString(forIso180135(ISO180135Headers.ISSUING_JURISDICTION), forIso232202(ISO232202Headers.ISSUING_SUBDIVISION),
                forEUDIPid(EUDIPIDHeaders.ISSUING_JURISDICTION));
    }

    @Override
    public VerifiedClaimString getResidentAddressCity() {
        return getAsString(
                forIso180135(ISO180135Headers.RESIDENT_CITY),
                forIso232202(ISO232202Headers.RESIDENT_CITY, ISO232202Headers.RESIDENT_CITY_UNICODE, ISO232202Headers.RESIDENT_CITY_LATIN1),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_CITY)
        );
    }

    @Override
    public VerifiedClaimString getResidentAddressState() {
        return getAsString(forIso180135(ISO180135Headers.RESIDENT_STATE),
                forIso232202(ISO232202Headers.RESIDENT_STATE, ISO232202Headers.RESIDENT_STATE_LATIN1),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_STATE));
    }

    @Override
    public VerifiedClaimString getResidentAddressPostalCode() {
        return getAsString(forIso180135(ISO180135Headers.RESIDENT_POSTAL_CODE), forIso232202(ISO232202Headers.RESIDENT_POSTAL_CODE),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_POSTAL_CODE)
        );
    }

    @Override
    public VerifiedClaimString getResidentAddressCountry() {
        return getAsString(forIso180135(ISO180135Headers.RESIDENT_COUNTRY), forIso232202(ISO232202Headers.RESIDENT_COUNTRY),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_COUNTRY));
    }

    @Override
    public List<VerifiedClaimBiometricTemplateXX> getBiometricTemplate() {
        List<VerifiedClaim> biometricTemplateXXClaims = getAllStartingWith(forIso180135(ISO180135Headers.BIOMETRIC_TEMPLATE_XX));
        VerifiedClaim biometricTemplateFace = get(forIso232202(ISO232202Headers.BIOMETRIC_TEMPLATE_FACE));
        if (biometricTemplateFace != null) {
            biometricTemplateXXClaims.add(biometricTemplateFace);
        }
        if (Utils.isCollectionEmpty(biometricTemplateXXClaims)) {
            return Collections.emptyList();
        }

        final List<VerifiedClaimBiometricTemplateXX> result = new ArrayList<>();
        for (VerifiedClaim claim : biometricTemplateXXClaims) {
            if (claim.isBinaryValueType()) {
                result.add(new MdocVerifiedClaimBiometricTemplateXX((VerifiedClaimByteString) claim));
            } else {
                LOG.warn("Claim with name '{}' shall have a value of CBOR Byte String type!", claim.getName());
            }
        }
        return result;
    }

    @Override
    public VerifiedClaimByteString getSignatureUsualMark() {
        return getAsByteString(forIso180135(ISO180135Headers.SIGNATURE));
    }

    @Override
    public VerifiedClaimString getVersion() {
        return getAsString(forIso180135Implicit(MdocConstants.VERSION), forIso232202Implicit(MdocConstants.VERSION));
    }

    @Override
    public VerifiedClaimString getDocType() {
        return getAsString(forIso180135Implicit(MdocConstants.DOC_TYPE), forIso232202Implicit(MdocConstants.DOC_TYPE));
    }

    @Override
    public VerifiedClaimValidityInfo getValidityInfo() {
        VerifiedClaimMap validityInfo = getAsMap(forIso180135Implicit(MdocConstants.VALIDITY_INFO), forIso232202Implicit(MdocConstants.VALIDITY_INFO));
        if (validityInfo != null) {
            return new MdocVerifiedClaimValidityInfo(validityInfo);
        }
        return null;
    }

    @Override
    public VerifiedClaimByteString getFingerprint() {
        return getAsByteString(forIso232202(ISO232202Headers.FINGERPRINT));
    }

    @Override
    public VerifiedClaimString getBusinessName() {
        return getAsString(forIso232202(ISO232202Headers.BUSINESS_NAME, ISO232202Headers.BUSINESS_NAME_UNICODE, ISO232202Headers.BUSINESS_NAME_LATIN1));
    }

    @Override
    public VerifiedClaimString getOrganizationName() {
        return getAsString(forIso232202(ISO232202Headers.ORGANIZATION_NAME, ISO232202Headers.ORGANIZATION_NAME_UNICODE, ISO232202Headers.ORGANIZATION_NAME_LATIN1));
    }

    @Override
    public VerifiedClaimString getBirthFullName() {
        return getAsString(forIso232202(ISO232202Headers.NAME_AT_BIRTH));
    }

    @Override
    public VerifiedClaimString getProfession() {
        return getAsString(forIso232202(ISO232202Headers.PROFESSION));
    }

    @Override
    public VerifiedClaimString getRelationshipFather() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_FATHER));
    }

    @Override
    public VerifiedClaimString getRelationshipMother() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_MOTHER));
    }

    @Override
    public VerifiedClaimString getRelationshipParent() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_PARENT));
    }

    @Override
    public VerifiedClaimString getRelationshipSon() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_SON));
    }

    @Override
    public VerifiedClaimString getRelationshipDaughter() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_DAUGHTER));
    }

    @Override
    public VerifiedClaimString getRelationshipBrother() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_BROTHER));
    }

    @Override
    public VerifiedClaimString getRelationshipSister() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_SISTER));
    }

    @Override
    public VerifiedClaimString getRelationshipSibling() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_SIBLING));
    }

    @Override
    public VerifiedClaimString getRelationshipSpouse() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_SPOUSE));
    }

    @Override
    public VerifiedClaimString getRelationshipFatherInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_FATHER_IN_LAW));
    }

    @Override
    public VerifiedClaimString getRelationshipMotherInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_MOTHER_IN_LAW));
    }

    @Override
    public VerifiedClaimString getRelationshipParentInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_PARENT_IN_LAW));
    }

    @Override
    public VerifiedClaimString getRelationshipSonInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_SON_IN_LAW));
    }

    @Override
    public VerifiedClaimString getRelationshipDaughterInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_DAUGHTER_IN_LAW));
    }

    @Override
    public VerifiedClaimString getRelationshipChildInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_CHILD_IN_LAW));
    }

    @Override
    public VerifiedClaimString getRelationshipParentalAuthority() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_PARENTAL_AUTHORITY));
    }

    @Override
    public VerifiedClaimString getRelationshipLegalRepresentative() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_LEGAL_REPRESENTATIVE));
    }

    @Override
    public VerifiedClaimString getRelationshipAgent() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_AGENT));
    }

    @Override
    public VerifiedClaimString getDocumentType() {
        return getAsString(forIso232202(ISO232202Headers.DOCUMENT_TYPE));
    }

    @Override
    public VerifiedClaimDate getAdministrativeExpirationDate() {
        return getAsDateOrDateTime(forIso180135(ISO180135Headers.EXPIRY_DATE), forIso232202(ISO232202Headers.EXPIRY_DATE),
                forEUDIPid(EUDIPIDHeaders.EXPIRY_DATE));
    }

    @Override
    public VerifiedClaimDate getAdministrativeIssuanceDate() {
        return getAsDateOrDateTime(forIso180135(ISO180135Headers.ISSUE_DATE), forIso232202(ISO232202Headers.ISSUE_DATE),
                forEUDIPid(EUDIPIDHeaders.ISSUANCE_DATE));
    }

    @Override
    public VerifiedClaimString getResidentAddressStreet() {
        return getAsString(forIso232202(ISO232202Headers.RESIDENT_STREET, ISO232202Headers.RESIDENT_STREET_LATIN1),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_STREET));
    }

    @Override
    public VerifiedClaimString getResidentAddressHouseNumber() {
        return getAsString(forEUDIPid(EUDIPIDHeaders.RESIDENT_HOUSE_NUMBER));
    }

    @Override
    public VerifiedClaimString getTrustAnchor() {
        return getAsString(forEUDIPid(EUDIPIDHeaders.TRUST_ANCHOR));
    }

    @Override
    public VerifiedClaimString getIssuingAuthorityRegistrationIdentifier() {
        return getAsString(forEtsi194721(ETSI194721Headers.ISSUING_REGISTRATION_IDENTIFIER));
    }

    @Override
    public VerifiedClaim getOneTimeUse() {
        /* EAA-6.2.8.2-03: The oneTime data element shall have the bool CBOR type.  */
        return getAsBoolean(forEtsi194721(ETSI194721Headers.ONE_TIME));
    }

    @Override
    public VerifiedClaim getShortLived() {
        /* EAA-6.2.12-03: The shortLived data element shall have the bool CBOR type. */
        return getAsBoolean(forEtsi194721(ETSI194721Headers.SHORT_LIVED));
    }

    @Override
    public VerifiedClaimArray getEvidence() {
        /*
         * EAA-6.2.9-01: An ISO/IEC-mdoc attestation shall not incorporate any data element implementing the semantics
         * specified in clause 4.2.10 of the present document.
         */
        return null;
    }

    @Override
    public VerifiedClaimAttestedAttributesSubject getAttestedAttributesSubject() {
        VerifiedClaimMap subAttrs = getAsMap(forEtsi194721(ETSI194721Headers.SUB_ATTRS));
        if (subAttrs != null) {
            return new MdocVerifiedClaimAttestedAttributesSubject(subAttrs);
        }
        return null;
    }

    /**
     * Gets the value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link VerifiedClaim}
     */
    protected VerifiedClaim get(DataElementReference... references) {
        for (DataElementReference dataElementReference : references) {
            String namespace = dataElementReference.getNamespace();
            for (String headerName : dataElementReference.getHeaderNames()) {
                VerifiedClaim value = super.get(headerName);
                if (value != null && (namespace == null || namespace.equals(value.getNamespace()))) {
                    return value;
                }
            }
        }
        return null;
    }

    /**
     * This method allows extraction of all claims with header names starting with the given data element reference.
     * E.g. this method allows extraction values according to the pattern "age_over_NN", where NN can be any data.
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link VerifiedClaim}
     */
    protected List<VerifiedClaim> getAllStartingWith(DataElementReference... references) {
        final List<VerifiedClaim> result = new ArrayList<>();
        Map<String, VerifiedClaim> claimMap = super.getMapValue();
        for (DataElementReference dataElementReference : references) {
            String namespace = dataElementReference.getNamespace();
            for (String headerName : dataElementReference.getHeaderNames()) {
                for (Map.Entry<String, VerifiedClaim> claimMapEntry : claimMap.entrySet()) {
                    if (claimMapEntry.getKey().startsWith(headerName) &&
                            (namespace == null || namespace.equals(claimMapEntry.getValue().getNamespace()))) {
                        result.add(claimMapEntry.getValue());
                    }
                }
            }
        }
        return result;
    }

    /**
     * Gets the map value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link VerifiedClaimMap}
     */
    protected VerifiedClaimMap getAsMap(DataElementReference... references) {
        VerifiedClaim claim = get(references);
        return getAsMap(claim);
    }

    /**
     * Gets the array value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link VerifiedClaimArray}
     */
    protected VerifiedClaimArray getAsArray(DataElementReference... references) {
        VerifiedClaim claim = get(references);
        return getAsArray(claim);
    }

    /**
     * Gets the number value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link VerifiedClaimNumber}
     */
    protected VerifiedClaimNumber getAsNumber(DataElementReference... references) {
        VerifiedClaim claim = get(references);
        return getAsNumber(claim);
    }

    /**
     * Gets the String value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link VerifiedClaimString}
     */
    protected VerifiedClaimString getAsString(DataElementReference... references) {
        VerifiedClaim claim = get(references);
        return getAsString(claim);
    }

    /**
     * Gets the boolean value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link VerifiedClaimBoolean}
     */
    protected VerifiedClaimBoolean getAsBoolean(DataElementReference... references) {
        VerifiedClaim claim = get(references);
        return getAsBoolean(claim);
    }

    /**
     * Gets the byte string value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link VerifiedClaimByteString}
     */
    protected VerifiedClaimByteString getAsByteString(DataElementReference... references) {
        VerifiedClaim claim = get(references);
        return getAsByteString(claim);
    }

    /**
     * Gets the date value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link VerifiedClaimDate}
     */
    protected VerifiedClaimDate getAsDate(DataElementReference... references) {
        VerifiedClaim claim = get(references);
        return getAsDate(claim);
    }

    /**
     * Gets the date-time value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link VerifiedClaimDate}
     */
    protected VerifiedClaimDate getAsDateTime(DataElementReference... references) {
        VerifiedClaim claim = get(references);
        return getAsDateTime(claim);
    }

    /**
     * Gets the date or date-time value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link VerifiedClaimDate}
     */
    protected VerifiedClaimDate getAsDateOrDateTime(DataElementReference... references) {
        VerifiedClaim claim = get(references);
        return getAsDateOrDateTime(claim);
    }

    /**
     * Creates a data element reference to ISO 18013-5 header parameter names
     *
     * @param headerNames array of {@link String}s
     * @return {@link DataElementReference}
     */
    protected DataElementReference forIso180135(final String... headerNames) {
        return new DataElementReference(MdocConstants.ISO18013_5_NAMESPACE, headerNames);
    }

    /**
     * Creates a data element reference to ISO 18013-5 header parameter names which are non disclosable
     *
     * @param headerNames array of {@link String}s
     * @return {@link DataElementReference}
     */
    protected DataElementReference forIso180135Implicit(final String... headerNames) {
        return new DataElementReference(null, headerNames);
    }

    /**
     * Creates a data element reference to ISO 23220-2 header parameter names
     *
     * @param headerNames array of {@link String}s
     * @return {@link DataElementReference}
     */
    protected DataElementReference forIso232202(final String... headerNames) {
        return new DataElementReference(MdocConstants.ISO23220_1_NAMESPACE, headerNames);
    }

    /**
     * Creates a data element reference to ISO 23220-2 header parameter names which are non disclosable
     *
     * @param headerNames array of {@link String}s
     * @return {@link DataElementReference}
     */
    protected DataElementReference forIso232202Implicit(final String... headerNames) {
        return new DataElementReference(null, headerNames);
    }

    /**
     * Creates a data element reference to ETSI TS 119 472-1 header parameter names
     * for the mobile driving license (mDL)
     *
     * @param headerNames array of {@link String}s
     * @return {@link DataElementReference}
     */
    protected DataElementReference forEtsi194721(final String... headerNames) {
        return new DataElementReference(MdocConstants.ETSI_19472_1_NAMESPACE, headerNames);
    }

    /**
     * Creates a data element reference to EUDI PID header parameter names
     *
     * @param headerNames array of {@link String}s
     * @return {@link DataElementReference}
     */
    protected DataElementReference forEUDIPid(final String... headerNames) {
        return new DataElementReference(MdocConstants.EUDI_PID_NAMESPACE, headerNames);
    }

    /**
     * Internal class used for a data element reference definition for data extraction
     */
    private static final class DataElementReference implements Serializable {

        private static final long serialVersionUID = 8026021615590289170L;

        /** Attribute namespace */
        private final String namespace;

        /** Accepted header names */
        private final String[] headerNames;

        /**
         * Default constructor
         *
         * @param namespace {@link String}
         * @param headerNames array of {@link String}s
         */
        private DataElementReference(final String namespace, final String... headerNames) {
            this.namespace = namespace;
            this.headerNames = headerNames;
        }

        /**
         * Gets attribute namespace
         *
         * @return {@link String}
         */
        public String getNamespace() {
            return namespace;
        }

        /**
         * Gets attribute possible names
         *
         * @return {@link String}s
         */
        public String[] getHeaderNames() {
            return headerNames;
        }

    }

}
