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
package eu.europa.esig.dss.eaa.mdoc.validation;

import eu.europa.esig.dss.eaa.mdoc.ETSI194721Headers;
import eu.europa.esig.dss.eaa.mdoc.EUDIPIDHeaders;
import eu.europa.esig.dss.eaa.mdoc.ISO180135Headers;
import eu.europa.esig.dss.eaa.mdoc.ISO232202Headers;
import eu.europa.esig.dss.eaa.mdoc.MdocConstants;
import eu.europa.esig.dss.eaa.mdoc.claim.MdocBiometricTemplateXX;
import eu.europa.esig.dss.eaa.mdoc.claim.MdocClaimAgeOverNN;
import eu.europa.esig.dss.eaa.mdoc.claim.MdocClaimAttestedAttributesSubject;
import eu.europa.esig.dss.eaa.mdoc.claim.MdocClaimBirthDate;
import eu.europa.esig.dss.eaa.mdoc.claim.MdocClaimDeviceKeyInfo;
import eu.europa.esig.dss.eaa.mdoc.claim.MdocClaimDrivingPrivileges;
import eu.europa.esig.dss.eaa.mdoc.claim.MdocClaimMap;
import eu.europa.esig.dss.eaa.mdoc.claim.MdocClaimPlaceOfBirth;
import eu.europa.esig.dss.eaa.mdoc.claim.MdocClaimStatus;
import eu.europa.esig.dss.eaa.mdoc.claim.MdocClaimValidityInfo;
import eu.europa.esig.dss.model.eaa.claim.Claim;
import eu.europa.esig.dss.model.eaa.claim.ClaimAddress;
import eu.europa.esig.dss.model.eaa.claim.ClaimAgeOverNN;
import eu.europa.esig.dss.model.eaa.claim.ClaimAgeEqualOrOver;
import eu.europa.esig.dss.model.eaa.claim.ClaimArray;
import eu.europa.esig.dss.model.eaa.claim.ClaimAttestedAttributesSubject;
import eu.europa.esig.dss.model.eaa.claim.ClaimBiometricTemplateXX;
import eu.europa.esig.dss.model.eaa.claim.ClaimBoolean;
import eu.europa.esig.dss.model.eaa.claim.ClaimByteString;
import eu.europa.esig.dss.model.eaa.claim.ClaimCredentialSubject;
import eu.europa.esig.dss.model.eaa.claim.ClaimDate;
import eu.europa.esig.dss.model.eaa.claim.ClaimDeviceKey;
import eu.europa.esig.dss.model.eaa.claim.ClaimDrivingPrivileges;
import eu.europa.esig.dss.model.eaa.claim.ClaimIntegrity;
import eu.europa.esig.dss.model.eaa.claim.ClaimMap;
import eu.europa.esig.dss.model.eaa.claim.ClaimNumber;
import eu.europa.esig.dss.model.eaa.claim.ClaimStatus;
import eu.europa.esig.dss.model.eaa.claim.ClaimString;
import eu.europa.esig.dss.model.eaa.claim.ClaimValidityInfo;
import eu.europa.esig.dss.spi.eaa.AttestationPayload;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Mdoc's representation of an EAA payload
 *
 */
public class MdocAttestationPayload extends MdocClaimMap implements AttestationPayload {

    private static final long serialVersionUID = -5947789662835061427L;

    private static final Logger LOG = LoggerFactory.getLogger(MdocAttestationPayload.class);

    /**
     * Default constructor
     *
     * @param verifiedPayloadMap {@link ClaimMap}
     * @param docType {@link String}
     */
    public MdocAttestationPayload(final ClaimMap verifiedPayloadMap, final String docType) {
        super(verifiedPayloadMap.getMapValue());
    }

    @Override
    public ClaimString getIdentifier() {
        // not applicable
        return null;
    }

    @Override
    public ClaimString getIssuer() {
        // not applicable
        return null;
    }

    @Override
    public ClaimString getSubject() {
        // not applicable
        return null;
    }

    @Override
    public ClaimArray getAudience() {
        // not applicable
        return null;
    }

    @Override
    public ClaimDate getIssuedAtTime() {
        // see ValidityInfo
        return null;
    }

    @Override
    public ClaimDate getNotBeforeTime() {
        // see ValidityInfo
        return null;
    }

    @Override
    public ClaimDate getExpirationTime() {
        // see ValidityInfo
        return null;
    }

    @Override
    public ClaimDate getUpdatedAtTime() {
        // see ValidityInfo
        return null;
    }

    @Override
    public ClaimDeviceKey getDeviceKey() {
        ClaimMap deviceKeyInfo = getAsMap(forIso180135Implicit(MdocConstants.DEVICE_KEY_INFO), forIso232202Implicit(MdocConstants.DEVICE_KEY_INFO));
        if (deviceKeyInfo != null) {
            return new MdocClaimDeviceKeyInfo(deviceKeyInfo);
        }
        return null;
    }

    @Override
    public ClaimString getCategory() {
        return getAsString(forEtsi194721(ETSI194721Headers.CATEGORY), forEUDIPid(EUDIPIDHeaders.ATTESTATION_LEGAL_CATEGORY));
    }

    @Override
    public ClaimString getVerifiableCredentialsType() {
        return null;
    }

    @Override
    public ClaimIntegrity getVerifiableCredentialsTypeIntegrity() {
        return null;
    }

    @Override
    public ClaimStatus getStatus() {
        ClaimMap statusClaim = getAsMap(MdocConstants.STATUS);
        if (statusClaim == null) {
            // Can be defined with a Long key
            Object statusClaimObject = value.get(MdocConstants.STATUS_LONG);
            if (statusClaimObject != null) {
                Claim claim = createClaim(MdocConstants.STATUS_LONG.getValueAsString(), statusClaimObject);
                if (claim != null && claim.isMapValueType()) {
                    statusClaim = (ClaimMap) claim;
                }
            }
        }
        if (statusClaim != null) {
            return new MdocClaimStatus(statusClaim);
        }
        return null;
    }

    @Override
    public ClaimString getNonce() {
        return null;
    }

    @Override
    public ClaimString getFullName() {
        return getAsString(forIso232202(ISO232202Headers.FULL_NAME, ISO232202Headers.FULL_NAME_LATIN1));
    }

    @Override
    public ClaimString getGivenName() {
        return getAsString(
                forIso180135(ISO180135Headers.GIVEN_NAME, ISO180135Headers.GIVEN_NAME_NATIONAL_CHARACTER),
                forIso232202(ISO232202Headers.GIVEN_NAME, ISO232202Headers.GIVEN_NAME_UNICODE, ISO232202Headers.GIVEN_NAME_LATIN1),
                forEUDIPid(EUDIPIDHeaders.GIVEN_NAME)
        );
    }

    @Override
    public ClaimString getFamilyName() {
        return getAsString(
                forIso180135(ISO180135Headers.FAMILY_NAME, ISO180135Headers.FAMILY_NAME_NATIONAL_CHARACTER),
                forIso232202(ISO232202Headers.FAMILY_NAME, ISO232202Headers.FAMILY_NAME_UNICODE, ISO232202Headers.FAMILY_NAME_LATIN1),
                forEUDIPid(EUDIPIDHeaders.FAMILY_NAME)
        );
    }

    @Override
    public ClaimString getMiddleName() {
        return null;
    }

    @Override
    public ClaimString getNickname() {
        return null;
    }

    @Override
    public ClaimString getShortName() {
        return null;
    }

    @Override
    public ClaimString getProfileUrl() {
        return null;
    }

    @Override
    public ClaimString getPictureUrl() {
        return null;
    }

    @Override
    public ClaimString getWebsiteUrl() {
        return null;
    }

    @Override
    public ClaimString getEmail() {
        return getAsString(forIso232202(ISO232202Headers.EMAIL_ADDRESS), forEUDIPid(EUDIPIDHeaders.EMAIL_ADDRESS));
    }

    @Override
    public ClaimBoolean getEmailVerified() {
        return null;
    }

    @Override
    public ClaimNumber getGender() {
        return getAsNumber(forIso180135(ISO180135Headers.SEX), forIso232202(ISO232202Headers.SEX), forEUDIPid(EUDIPIDHeaders.SEX));
    }

    @Override
    public Claim getBirthdate() {
        ClaimDate birthdate = getAsDate(forIso180135(ISO180135Headers.BIRTH_DATE), forEUDIPid(EUDIPIDHeaders.BIRTH_DATE));
        if (birthdate != null) {
            return birthdate;
        }
        ClaimMap birthdateMap = getAsMap(forIso232202(ISO232202Headers.BIRTH_DATE));
        if (birthdateMap != null) {
            return new MdocClaimBirthDate(birthdateMap);
        }
        return null;
    }

    @Override
    public ClaimString getTimezone() {
        return null;
    }

    @Override
    public ClaimString getLocale() {
        return null;
    }

    @Override
    public ClaimAddress getAddress() {
        // see #getPostalAddress, #getResidentAddressCity, etc.
        return null;
    }

    @Override
    public ClaimString getPhoneNumber() {
        return getAsString(forIso232202(ISO232202Headers.TELEPHONE_NUMBER));
    }

    @Override
    public ClaimBoolean getPhoneNumberVerified() {
        return null;
    }

    @Override
    public Claim getPlaceOfBirth() {
        ClaimString placeOfBirth = getAsString(forIso180135(ISO180135Headers.BIRTH_PLACE), forIso232202(ISO232202Headers.BIRTHPLACE));
        if (placeOfBirth != null) {
            return placeOfBirth;
        }
        ClaimMap placeOfBirthMap = getAsMap(forEUDIPid(EUDIPIDHeaders.PLACE_OF_BIRTH));
        if (placeOfBirthMap != null) {
            return new MdocClaimPlaceOfBirth(placeOfBirthMap);
        }
        return null;
    }

    @Override
    public Claim getNationalities() {
        ClaimString nationalities = getAsString(forIso180135(ISO180135Headers.NATIONALITY), forIso232202(ISO232202Headers.NATIONALITY));
        if (nationalities != null) {
            return nationalities;
        }
        return getAsArray(forEUDIPid(EUDIPIDHeaders.NATIONALITY));
    }

    @Override
    public ClaimString getBirthGivenName() {
        return getAsString(forEUDIPid(EUDIPIDHeaders.GIVEN_NAME_BIRTH));
    }

    @Override
    public ClaimString getBirthFamilyName() {
        return getAsString(forEUDIPid(EUDIPIDHeaders.FAMILY_NAME_BIRTH));
    }

    @Override
    public ClaimString getBirthMiddleName() {
        return null;
    }

    @Override
    public ClaimString getSalutation() {
        return null;
    }

    @Override
    public ClaimString getTitle() {
        return getAsString(forIso232202(ISO232202Headers.TITLE));
    }

    @Override
    public ClaimString getMobilePhoneNumber() {
        return getAsString(forEUDIPid(EUDIPIDHeaders.MOBILE_PHONE_NUMBER));
    }

    @Override
    public ClaimString getPseudonym() {
        return getAsString(forEtsi194721(ETSI194721Headers.ALSO_KNOWN_AS));
    }

    @Override
    public List<ClaimCredentialSubject> getCredentialSubjects() {
        return null;
    }

    @Override
    public ClaimString getIssuingCountry() {
        return getAsString(forIso180135(ISO180135Headers.ISSUING_COUNTRY), forIso232202(ISO232202Headers.ISSUING_COUNTRY),
                forEUDIPid(EUDIPIDHeaders.ISSUING_COUNTRY));
    }

    @Override
    public ClaimString getIssuingAuthority() {
        return getAsString(
                forIso180135(ISO180135Headers.ISSUING_AUTHORITY),
                forIso232202(ISO232202Headers.ISSUING_AUTHORITY, ISO232202Headers.ISSUING_AUTHORITY_UNICODE, ISO232202Headers.ISSUING_AUTHORITY_LATIN1),
                forEUDIPid(EUDIPIDHeaders.ISSUING_AUTHORITY)
        );
    }

    @Override
    public ClaimString getDocumentNumber() {
        return getAsString(forIso180135(ISO180135Headers.LICENCE_NUMBER), forIso232202(ISO232202Headers.DOCUMENT_NUMBER),
                forEUDIPid(EUDIPIDHeaders.DOCUMENT_NUMBER));
    }

    @Override
    public ClaimByteString getPortrait() {
        return getAsByteString(forIso180135(ISO180135Headers.PORTRAIT), forIso232202(ISO232202Headers.PORTRAIT), forEUDIPid(EUDIPIDHeaders.PORTRAIT));
    }

    @Override
    public ClaimDrivingPrivileges getDrivingPrivileges() {
        ClaimArray claimDrivingPrivileges = getAsArray(forIso180135(ISO180135Headers.DRIVING_PRIVILEGES));
        if (claimDrivingPrivileges != null) {
            return new MdocClaimDrivingPrivileges(claimDrivingPrivileges);
        }
        return null;
    }

    @Override
    public ClaimString getUNDistinguishingSign() {
        return getAsString(forIso180135(ISO180135Headers.UN_DISTINGUISHING_SIGN));
    }

    @Override
    public ClaimString getPersonalAdministrativeNumber() {
        return getAsString(forIso180135(ISO180135Headers.ADMINISTRATIVE_NUMBER), forEUDIPid(EUDIPIDHeaders.PERSONAL_ADMINISTRATIVE_NUMBER));
    }

    @Override
    public ClaimNumber getHeight() {
        return getAsNumber(forIso180135(ISO180135Headers.HEIGHT), forIso232202(ISO232202Headers.HEIGHT));
    }

    @Override
    public ClaimNumber getWeight() {
        return getAsNumber(forIso180135(ISO180135Headers.WEIGHT), forIso232202(ISO232202Headers.WEIGHT));
    }

    @Override
    public ClaimString getEyeColour() {
        return getAsString(forIso180135(ISO180135Headers.EYE_COLOUR));
    }

    @Override
    public ClaimString getHairColour() {
        return getAsString(forIso180135(ISO180135Headers.HAIR_COLOUR));
    }

    @Override
    public ClaimString getPostalAddress() {
        return getAsString(
                forIso180135(ISO180135Headers.RESIDENT_ADDRESS),
                forIso232202(ISO232202Headers.RESIDENT_ADDRESS, ISO232202Headers.RESIDENT_ADDRESS_UNICODE, ISO232202Headers.RESIDENT_ADDRESS_LATIN1),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_ADDRESS)
        );
    }

    @Override
    public ClaimDate getPortraitCaptureDate() {
        return getAsDate(forIso180135(ISO180135Headers.PORTRAIT_CAPTURE_DATE), forIso232202(ISO232202Headers.PORTRAIT_CAPTURE_DATE));
    }

    @Override
    public ClaimNumber getAgeInYears() {
        return getAsNumber(forIso180135(ISO180135Headers.AGE_IN_YEARS), forIso232202(ISO232202Headers.AGE_IN_YEARS));
    }

    @Override
    public ClaimNumber getAgeBirthYear() {
        return getAsNumber(forIso180135(ISO180135Headers.AGE_BIRTH_YEAR), forIso232202(ISO232202Headers.AGE_BIRTH_YEAR));
    }

    @Override
    public ClaimAgeEqualOrOver getAgeEqualOrOver() {
        return null;
    }

    @Override
    public List<ClaimAgeOverNN> getAgeOverNN() {
        List<Claim> ageOverNNClaims = getAllStartingWith(forIso180135(ISO180135Headers.AGE_OVER_NN), forIso232202(ISO232202Headers.AGE_OVER_NN));
        if (Utils.isCollectionEmpty(ageOverNNClaims)) {
            return Collections.emptyList();
        }
        final List<ClaimAgeOverNN> result = new ArrayList<>();
        for (Claim claim : ageOverNNClaims) {
            if (claim.isBooleanValueType()) {
                result.add(new MdocClaimAgeOverNN((ClaimBoolean) claim));
            } else {
                LOG.warn("Claim with name '{}' shall have a value of CBOR Boolean type!", claim.getName());
            }
        }
        return result;
    }

    @Override
    public ClaimString getIssuingJurisdiction() {
        return getAsString(forIso180135(ISO180135Headers.ISSUING_JURISDICTION), forIso232202(ISO232202Headers.ISSUING_SUBDIVISION),
                forEUDIPid(EUDIPIDHeaders.ISSUING_JURISDICTION));
    }

    @Override
    public ClaimString getResidentAddressCity() {
        return getAsString(
                forIso180135(ISO180135Headers.RESIDENT_CITY),
                forIso232202(ISO232202Headers.RESIDENT_CITY, ISO232202Headers.RESIDENT_CITY_UNICODE, ISO232202Headers.RESIDENT_CITY_LATIN1),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_CITY)
        );
    }

    @Override
    public ClaimString getResidentAddressState() {
        return getAsString(forIso180135(ISO180135Headers.RESIDENT_STATE),
                forIso232202(ISO232202Headers.RESIDENT_STATE, ISO232202Headers.RESIDENT_STATE_LATIN1),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_STATE));
    }

    @Override
    public ClaimString getResidentAddressPostalCode() {
        return getAsString(forIso180135(ISO180135Headers.RESIDENT_POSTAL_CODE), forIso232202(ISO232202Headers.RESIDENT_POSTAL_CODE),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_POSTAL_CODE)
        );
    }

    @Override
    public ClaimString getResidentAddressCountry() {
        return getAsString(forIso180135(ISO180135Headers.RESIDENT_COUNTRY), forIso232202(ISO232202Headers.RESIDENT_COUNTRY),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_COUNTRY));
    }

    @Override
    public List<ClaimBiometricTemplateXX> getBiometricTemplate() {
        List<Claim> biometricTemplateXXClaims = getAllStartingWith(forIso180135(ISO180135Headers.BIOMETRIC_TEMPLATE_XX));
        Claim biometricTemplateFace = get(forIso232202(ISO232202Headers.BIOMETRIC_TEMPLATE_FACE));
        if (biometricTemplateFace != null) {
            biometricTemplateXXClaims.add(biometricTemplateFace);
        }
        if (Utils.isCollectionEmpty(biometricTemplateXXClaims)) {
            return Collections.emptyList();
        }

        final List<ClaimBiometricTemplateXX> result = new ArrayList<>();
        for (Claim claim : biometricTemplateXXClaims) {
            if (claim.isBinaryValueType()) {
                result.add(new MdocBiometricTemplateXX((ClaimByteString) claim));
            } else {
                LOG.warn("Claim with name '{}' shall have a value of CBOR Byte String type!", claim.getName());
            }
        }
        return result;
    }

    @Override
    public ClaimByteString getSignatureUsualMark() {
        return getAsByteString(forIso180135(ISO180135Headers.SIGNATURE));
    }

    @Override
    public ClaimString getVersion() {
        return getAsString(forIso180135Implicit(MdocConstants.VERSION), forIso232202Implicit(MdocConstants.VERSION));
    }

    @Override
    public ClaimString getDocType() {
        return getAsString(forIso180135Implicit(MdocConstants.DOC_TYPE), forIso232202Implicit(MdocConstants.DOC_TYPE));
    }

    @Override
    public ClaimValidityInfo getValidityInfo() {
        ClaimMap validityInfo = getAsMap(forIso180135Implicit(MdocConstants.VALIDITY_INFO), forIso232202Implicit(MdocConstants.VALIDITY_INFO));
        if (validityInfo != null) {
            return new MdocClaimValidityInfo(validityInfo);
        }
        return null;
    }

    @Override
    public ClaimByteString getFingerprint() {
        return getAsByteString(forIso232202(ISO232202Headers.FINGERPRINT));
    }

    @Override
    public ClaimString getBusinessName() {
        return getAsString(forIso232202(ISO232202Headers.BUSINESS_NAME, ISO232202Headers.BUSINESS_NAME_UNICODE, ISO232202Headers.BUSINESS_NAME_LATIN1));
    }

    @Override
    public ClaimString getOrganizationName() {
        return getAsString(forIso232202(ISO232202Headers.ORGANIZATION_NAME, ISO232202Headers.ORGANIZATION_NAME_UNICODE, ISO232202Headers.ORGANIZATION_NAME_LATIN1));
    }

    @Override
    public ClaimString getBirthFullName() {
        return getAsString(forIso232202(ISO232202Headers.NAME_AT_BIRTH));
    }

    @Override
    public ClaimString getProfession() {
        return getAsString(forIso232202(ISO232202Headers.PROFESSION));
    }

    @Override
    public ClaimString getRelationshipFather() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_FATHER));
    }

    @Override
    public ClaimString getRelationshipMother() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_MOTHER));
    }

    @Override
    public ClaimString getRelationshipParent() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_PARENT));
    }

    @Override
    public ClaimString getRelationshipSon() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_SON));
    }

    @Override
    public ClaimString getRelationshipDaughter() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_DAUGHTER));
    }

    @Override
    public ClaimString getRelationshipBrother() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_BROTHER));
    }

    @Override
    public ClaimString getRelationshipSister() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_SISTER));
    }

    @Override
    public ClaimString getRelationshipSibling() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_SIBLING));
    }

    @Override
    public ClaimString getRelationshipSpouse() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_SPOUSE));
    }

    @Override
    public ClaimString getRelationshipFatherInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_FATHER_IN_LAW));
    }

    @Override
    public ClaimString getRelationshipMotherInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_MOTHER_IN_LAW));
    }

    @Override
    public ClaimString getRelationshipParentInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_PARENT_IN_LAW));
    }

    @Override
    public ClaimString getRelationshipSonInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_SON_IN_LAW));
    }

    @Override
    public ClaimString getRelationshipDaughterInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_DAUGHTER_IN_LAW));
    }

    @Override
    public ClaimString getRelationshipChildInLaw() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_CHILD_IN_LAW));
    }

    @Override
    public ClaimString getRelationshipParentalAuthority() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_PARENTAL_AUTHORITY));
    }

    @Override
    public ClaimString getRelationshipLegalRepresentative() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_LEGAL_REPRESENTATIVE));
    }

    @Override
    public ClaimString getRelationshipAgent() {
        return getAsString(forIso232202(ISO232202Headers.RELATIONSHIP_AGENT));
    }

    @Override
    public ClaimString getDocumentType() {
        return getAsString(forIso232202(ISO232202Headers.DOCUMENT_TYPE));
    }

    @Override
    public ClaimDate getAdministrativeExpirationDate() {
        return getAsDateOrDateTime(forIso180135(ISO180135Headers.EXPIRY_DATE), forIso232202(ISO232202Headers.EXPIRY_DATE),
                forEUDIPid(EUDIPIDHeaders.EXPIRY_DATE));
    }

    @Override
    public ClaimDate getAdministrativeIssuanceDate() {
        return getAsDateOrDateTime(forIso180135(ISO180135Headers.ISSUE_DATE), forIso232202(ISO232202Headers.ISSUE_DATE),
                forEUDIPid(EUDIPIDHeaders.ISSUANCE_DATE));
    }

    @Override
    public ClaimString getResidentAddressStreet() {
        return getAsString(forIso232202(ISO232202Headers.RESIDENT_STREET, ISO232202Headers.RESIDENT_STREET_LATIN1),
                forEUDIPid(EUDIPIDHeaders.RESIDENT_STREET));
    }

    @Override
    public ClaimString getResidentAddressHouseNumber() {
        return getAsString(forEUDIPid(EUDIPIDHeaders.RESIDENT_HOUSE_NUMBER));
    }

    @Override
    public ClaimString getTrustAnchor() {
        return getAsString(forEUDIPid(EUDIPIDHeaders.TRUST_ANCHOR));
    }

    @Override
    public ClaimString getIssuingAuthorityRegistrationIdentifier() {
        return getAsString(forEtsi194721(ETSI194721Headers.ISSUING_REGISTRATION_IDENTIFIER));
    }

    @Override
    public Claim getOneTimeUse() {
        /* EAA-6.2.8.2-03: The oneTime data element shall have the bool CBOR type.  */
        return getAsBoolean(forEtsi194721(ETSI194721Headers.ONE_TIME));
    }

    @Override
    public Claim getShortLived() {
        /* EAA-6.2.12-03: The shortLived data element shall have the bool CBOR type. */
        return getAsBoolean(forEtsi194721(ETSI194721Headers.SHORT_LIVED));
    }

    @Override
    public ClaimArray getEvidence() {
        /*
         * EAA-6.2.9-01: An ISO/IEC-mdoc EAA shall not incorporate any data element implementing the semantics
         * specified in clause 4.2.10 of the present document.
         */
        return null;
    }

    @Override
    public ClaimAttestedAttributesSubject getAttestedAttributesSubject() {
        ClaimMap subAttrs = getAsMap(forEtsi194721(ETSI194721Headers.SUB_ATTRS));
        if (subAttrs != null) {
            return new MdocClaimAttestedAttributesSubject(subAttrs);
        }
        return null;
    }

    /**
     * Gets the value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link Claim}
     */
    protected Claim get(DataElementReference... references) {
        for (DataElementReference dataElementReference : references) {
            String namespace = dataElementReference.getNamespace();
            for (String headerName : dataElementReference.getHeaderNames()) {
                Claim value = super.get(headerName);
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
     * @return {@link Claim}
     */
    protected List<Claim> getAllStartingWith(DataElementReference... references) {
        final List<Claim> result = new ArrayList<>();
        Map<String, Claim> claimMap = super.getMapValue();
        for (DataElementReference dataElementReference : references) {
            String namespace = dataElementReference.getNamespace();
            for (String headerName : dataElementReference.getHeaderNames()) {
                for (Map.Entry<String, Claim> claimMapEntry : claimMap.entrySet()) {
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
     * @return {@link ClaimMap}
     */
    protected ClaimMap getAsMap(DataElementReference... references) {
        Claim claim = get(references);
        return getAsMap(claim);
    }

    /**
     * Gets the array value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link ClaimArray}
     */
    protected ClaimArray getAsArray(DataElementReference... references) {
        Claim claim = get(references);
        return getAsArray(claim);
    }

    /**
     * Gets the number value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link ClaimNumber}
     */
    protected ClaimNumber getAsNumber(DataElementReference... references) {
        Claim claim = get(references);
        return getAsNumber(claim);
    }

    /**
     * Gets the String value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link ClaimString}
     */
    protected ClaimString getAsString(DataElementReference... references) {
        Claim claim = get(references);
        return getAsString(claim);
    }

    /**
     * Gets the boolean value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link ClaimBoolean}
     */
    protected ClaimBoolean getAsBoolean(DataElementReference... references) {
        Claim claim = get(references);
        return getAsBoolean(claim);
    }

    /**
     * Gets the byte string value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link ClaimByteString}
     */
    protected ClaimByteString getAsByteString(DataElementReference... references) {
        Claim claim = get(references);
        return getAsByteString(claim);
    }

    /**
     * Gets the date value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link ClaimDate}
     */
    protected ClaimDate getAsDate(DataElementReference... references) {
        Claim claim = get(references);
        return getAsDate(claim);
    }

    /**
     * Gets the date-time value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link ClaimDate}
     */
    protected ClaimDate getAsDateTime(DataElementReference... references) {
        Claim claim = get(references);
        return getAsDateTime(claim);
    }

    /**
     * Gets the date or date-time value for the found element matching the first {@code DataElementReference}
     *
     * @param references an array of {@link DataElementReference}s
     * @return {@link ClaimDate}
     */
    protected ClaimDate getAsDateOrDateTime(DataElementReference... references) {
        Claim claim = get(references);
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
     * for the mobile driving license (mDL) EAA
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
