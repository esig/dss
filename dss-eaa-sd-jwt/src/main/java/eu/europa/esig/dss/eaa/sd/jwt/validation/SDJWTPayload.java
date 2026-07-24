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
package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.eaa.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.eaa.sd.jwt.claim.SDJWTClaimAddress;
import eu.europa.esig.dss.eaa.sd.jwt.claim.SDJWTClaimAgeOverNNList;
import eu.europa.esig.dss.eaa.sd.jwt.claim.SDJWTClaimAttestedAttributesSubject;
import eu.europa.esig.dss.eaa.sd.jwt.claim.SDJWTClaimCredentialSubject;
import eu.europa.esig.dss.eaa.sd.jwt.claim.SDJWTClaimDeviceKey;
import eu.europa.esig.dss.eaa.sd.jwt.claim.SDJWTClaimIntegrity;
import eu.europa.esig.dss.eaa.sd.jwt.claim.SDJWTClaimMap;
import eu.europa.esig.dss.eaa.sd.jwt.claim.SDJWTClaimPlaceOfBirth;
import eu.europa.esig.dss.eaa.sd.jwt.claim.SDJWTClaimStatus;
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
import eu.europa.esig.dss.model.eaa.claim.ClaimNull;
import eu.europa.esig.dss.model.eaa.claim.ClaimNumber;
import eu.europa.esig.dss.model.eaa.claim.ClaimPlaceOfBirth;
import eu.europa.esig.dss.model.eaa.claim.ClaimStatus;
import eu.europa.esig.dss.model.eaa.claim.ClaimString;
import eu.europa.esig.dss.model.eaa.claim.ClaimValidityInfo;
import eu.europa.esig.dss.spi.eaa.AttestationPayload;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class implements a user-friendly access to the EAA payload elements of the SD-JWT token
 *
 */
public class SDJWTPayload extends SDJWTClaimMap implements AttestationPayload {

    private static final long serialVersionUID = -4552799683587409954L;

    /**
     * Constructor with a verified payload map, containing the attached disclosures, when applicable
     *
     * @param verifiedPayloadMap {@link String} json payload
     */
    public SDJWTPayload(final ClaimMap verifiedPayloadMap) {
        super(verifiedPayloadMap.getMapValue());
    }

    @Override
    public ClaimString getIdentifier() {
        return getAsString(SDJWTConstants.JWT_ID);
    }

    @Override
    public ClaimString getIssuer() {
        return getAsString(SDJWTConstants.ISSUER);
    }

    @Override
    public ClaimString getSubject() {
        return getAsString(SDJWTConstants.SUBJECT);
    }

    @Override
    public ClaimArray getAudience() {
        return getAsArray(SDJWTConstants.AUDIENCE);
    }

    @Override
    public ClaimDate getIssuedAtTime() {
        return getAsDateTime(SDJWTConstants.ISSUED_AT);
    }

    @Override
    public ClaimDate getNotBeforeTime() {
        return getAsDateTime(SDJWTConstants.NOT_BEFORE);
    }

    @Override
    public ClaimDate getExpirationTime() {
        return getAsDateTime(SDJWTConstants.EXPIRATION_TIME);
    }

    @Override
    public ClaimDate getUpdatedAtTime() {
        return getAsDateTime(SDJWTConstants.UPDATED_AT);
    }

    @Override
    public ClaimDeviceKey getDeviceKey() {
        ClaimMap cnf = getAsMap(SDJWTConstants.CNF);
        if (cnf != null) {
            return new SDJWTClaimDeviceKey(cnf);
        }
        return null;
    }

    @Override
    public ClaimString getCategory() {
        ClaimString category = getAsString(SDJWTConstants.CATEGORY);
        if (category != null) {
            return category;
        }
        return getAsString(SDJWTConstants.ATTESTATION_LEGAL_CATEGORY);
    }

    @Override
    public ClaimString getVerifiableCredentialsType() {
        return getAsString(SDJWTConstants.VERIFIABLE_CREDENTIALS_TYPE);
    }

    @Override
    public ClaimIntegrity getVerifiableCredentialsTypeIntegrity() {
        ClaimString metadataIntegrity = getAsString(SDJWTConstants.VERIFIABLE_CREDENTIALS_INTEGRITY);
        if (metadataIntegrity != null) {
            return new SDJWTClaimIntegrity(metadataIntegrity);
        }
        return null;
    }

    @Override
    public ClaimStatus getStatus() {
        ClaimMap statusClaim = getAsMap(SDJWTConstants.STATUS);
        if (statusClaim != null) {
            return new SDJWTClaimStatus(statusClaim);
        }
        return null;
    }

    @Override
    public ClaimString getNonce() {
        return getAsString(SDJWTConstants.NONCE);
    }

    @Override
    public ClaimString getFullName() {
        return getAsString(SDJWTConstants.USER_NAME);
    }

    @Override
    public ClaimString getGivenName() {
        return getAsString(SDJWTConstants.USER_GIVEN_NAME);
    }

    @Override
    public ClaimString getFamilyName() {
        return getAsString(SDJWTConstants.USER_FAMILY_NAME);
    }

    @Override
    public ClaimString getMiddleName() {
        return getAsString(SDJWTConstants.USER_MIDDLE_NAME);
    }

    @Override
    public ClaimString getNickname() {
        return getAsString(SDJWTConstants.USER_NICKNAME);
    }

    @Override
    public ClaimString getShortName() {
        return getAsString(SDJWTConstants.USER_PREFERRED_NICKNAME);
    }

    @Override
    public ClaimString getProfileUrl() {
        return getAsString(SDJWTConstants.USER_PROFILE);
    }

    @Override
    public ClaimString getPictureUrl() {
        return getAsString(SDJWTConstants.USER_PICTURE);
    }

    @Override
    public ClaimString getWebsiteUrl() {
        return getAsString(SDJWTConstants.USER_WEBSITE);
    }

    @Override
    public ClaimString getEmail() {
        return getAsString(SDJWTConstants.USER_EMAIL);
    }

    @Override
    public ClaimBoolean getEmailVerified() {
        return getAsBoolean(SDJWTConstants.USER_EMAIL_VERIFIED);
    }

    @Override
    public Claim getGender() {
        ClaimString userGender = getAsString(SDJWTConstants.USER_GENDER);
        if (userGender != null) {
            return userGender;
        }
        return getAsNumber(SDJWTConstants.SEX);
    }

    @Override
    public ClaimDate getBirthdate() {
        return getAsDate(SDJWTConstants.USER_BIRTHDATE);
    }

    @Override
    public ClaimString getTimezone() {
        return getAsString(SDJWTConstants.USER_ZONEINFO);
    }

    @Override
    public ClaimString getLocale() {
        return getAsString(SDJWTConstants.USER_LOCALE);
    }

    @Override
    public ClaimAddress getAddress() {
        ClaimMap claimAddress = getAsMap(SDJWTConstants.USER_ADDRESS);
        if (claimAddress != null) {
            return new SDJWTClaimAddress(claimAddress);
        }
        return null;
    }

    @Override
    public ClaimString getPhoneNumber() {
        return getAsString(SDJWTConstants.USER_PHONE_NUMBER);
    }

    @Override
    public ClaimBoolean getPhoneNumberVerified() {
        return getAsBoolean(SDJWTConstants.USER_PHONE_NUMBER_VERIFIED);
    }

    @Override
    public ClaimPlaceOfBirth getPlaceOfBirth() {
        ClaimMap claimPlaceOfBirth = getAsMap(SDJWTConstants.USER_PLACE_OF_BIRTH);
        if (claimPlaceOfBirth != null) {
            return new SDJWTClaimPlaceOfBirth(claimPlaceOfBirth);
        }
        return null;
    }

    @Override
    public ClaimArray getNationalities() {
        return getAsArray(SDJWTConstants.USER_NATIONALITIES);
    }

    @Override
    public ClaimString getBirthGivenName() {
        return getAsString(SDJWTConstants.USER_BIRTH_GIVEN_NAME);
    }

    @Override
    public ClaimString getBirthFamilyName() {
        return getAsString(SDJWTConstants.USER_BIRTH_FAMILY_NAME);
    }

    @Override
    public ClaimString getBirthMiddleName() {
        return getAsString(SDJWTConstants.USER_BIRTH_MIDDLE_NAME);
    }

    @Override
    public ClaimString getSalutation() {
        return getAsString(SDJWTConstants.USER_SALUTATION);
    }

    @Override
    public ClaimString getTitle() {
        return getAsString(SDJWTConstants.USER_TITLE);
    }

    @Override
    public ClaimString getMobilePhoneNumber() {
        return getAsString(SDJWTConstants.USER_MOBILE_PHONE_NUMBER);
    }

    @Override
    public ClaimString getPseudonym() {
        return getAsString(SDJWTConstants.USER_PSEUDONYM);
    }

    @Override
    public List<ClaimCredentialSubject> getCredentialSubjects() {
        ClaimMap claimCredentialSubjectAsMap = getAsMap(SDJWTConstants.CREDENTIAL_SUBJECT);
        if (claimCredentialSubjectAsMap != null) {
            return Collections.singletonList(new SDJWTClaimCredentialSubject(claimCredentialSubjectAsMap));
        }
        ClaimArray claimCredentialSubjectAsArray = getAsArray(SDJWTConstants.CREDENTIAL_SUBJECT);
        if (claimCredentialSubjectAsArray != null) {
            List<ClaimCredentialSubject> result = new ArrayList<>();
            for (Claim credentialSubject : claimCredentialSubjectAsArray.getListValue()) {
                if (credentialSubject.isMapValueType()) {
                    result.add(new SDJWTClaimCredentialSubject((ClaimMap) credentialSubject));
                }
            }
            return result;
        }
        return Collections.emptyList();
    }

    @Override
    public ClaimString getIssuingCountry() {
        return getAsString(SDJWTConstants.ISSUING_COUNTRY);
    }

    @Override
    public ClaimString getIssuingAuthority() {
        return getAsString(SDJWTConstants.ISSUING_AUTHORITY);
    }

    @Override
    public ClaimString getDocumentNumber() {
        return getAsString(SDJWTConstants.DOCUMENT_NUMBER);
    }

    @Override
    public ClaimByteString getPortrait() {
        return null;
    }

    @Override
    public ClaimDrivingPrivileges getDrivingPrivileges() {
        return null;
    }

    @Override
    public ClaimString getUNDistinguishingSign() {
        return null;
    }

    @Override
    public ClaimString getPersonalAdministrativeNumber() {
        return getAsString(SDJWTConstants.PERSONAL_ADMINISTRATIVE_NUMBER);
    }

    @Override
    public ClaimNumber getHeight() {
        return null;
    }

    @Override
    public ClaimNumber getWeight() {
        return null;
    }

    @Override
    public ClaimString getEyeColour() {
        return null;
    }

    @Override
    public ClaimString getHairColour() {
        return null;
    }

    @Override
    public ClaimString getPostalAddress() {
        return null;
    }

    @Override
    public ClaimDate getPortraitCaptureDate() {
        return null;
    }

    @Override
    public ClaimNumber getAgeInYears() {
        return getAsNumber(SDJWTConstants.AGE_IN_YEARS);
    }

    @Override
    public ClaimNumber getAgeBirthYear() {
        return getAsNumber(SDJWTConstants.AGE_BIRTH_YEAR);
    }

    @Override
    public ClaimAgeEqualOrOver getAgeEqualOrOver() {
        ClaimMap ageEqualOrOver = getAsMap(SDJWTConstants.AGE_EQUAL_OR_OVER);
        if (ageEqualOrOver != null) {
            return new SDJWTClaimAgeOverNNList(ageEqualOrOver);
        }
        return null;
    }

    @Override
    public List<ClaimAgeOverNN> getAgeOverNN() {
        return Collections.emptyList();
    }

    @Override
    public ClaimString getIssuingJurisdiction() {
        return getAsString(SDJWTConstants.ISSUING_JURISDICTION);
    }

    @Override
    public ClaimString getResidentAddressCity() {
        return null;
    }

    @Override
    public ClaimString getResidentAddressState() {
        return null;
    }

    @Override
    public ClaimString getResidentAddressPostalCode() {
        return null;
    }

    @Override
    public ClaimString getResidentAddressCountry() {
        return null;
    }

    @Override
    public List<ClaimBiometricTemplateXX> getBiometricTemplate() {
        return Collections.emptyList();
    }

    @Override
    public ClaimByteString getSignatureUsualMark() {
        return null;
    }

    @Override
    public ClaimString getVersion() {
        return null;
    }

    @Override
    public ClaimString getDocType() {
        return null;
    }

    @Override
    public ClaimValidityInfo getValidityInfo() {
        return null;
    }

    @Override
    public ClaimByteString getFingerprint() {
        return null;
    }

    @Override
    public ClaimString getBusinessName() {
        return null;
    }

    @Override
    public ClaimString getOrganizationName() {
        return null;
    }

    @Override
    public ClaimString getBirthFullName() {
        return null;
    }

    @Override
    public ClaimString getProfession() {
        return null;
    }

    @Override
    public ClaimString getRelationshipFather() {
        return null;
    }

    @Override
    public ClaimString getRelationshipMother() {
        return null;
    }

    @Override
    public ClaimString getRelationshipParent() {
        return null;
    }

    @Override
    public ClaimString getRelationshipSon() {
        return null;
    }

    @Override
    public ClaimString getRelationshipDaughter() {
        return null;
    }

    @Override
    public ClaimString getRelationshipBrother() {
        return null;
    }

    @Override
    public ClaimString getRelationshipSister() {
        return null;
    }

    @Override
    public ClaimString getRelationshipSibling() {
        return null;
    }

    @Override
    public ClaimString getRelationshipSpouse() {
        return null;
    }

    @Override
    public ClaimString getRelationshipFatherInLaw() {
        return null;
    }

    @Override
    public ClaimString getRelationshipMotherInLaw() {
        return null;
    }

    @Override
    public ClaimString getRelationshipParentInLaw() {
        return null;
    }

    @Override
    public ClaimString getRelationshipSonInLaw() {
        return null;
    }

    @Override
    public ClaimString getRelationshipDaughterInLaw() {
        return null;
    }

    @Override
    public ClaimString getRelationshipChildInLaw() {
        return null;
    }

    @Override
    public ClaimString getRelationshipParentalAuthority() {
        return null;
    }

    @Override
    public ClaimString getRelationshipLegalRepresentative() {
        return null;
    }

    @Override
    public ClaimString getRelationshipAgent() {
        return null;
    }

    @Override
    public ClaimString getDocumentType() {
        return null;
    }

    @Override
    public ClaimDate getAdministrativeExpirationDate() {
        // TODO : PID Rulebook and ETSI both define their own headers, check for conflict ?
        ClaimDate admExp = getAsDateTime(SDJWTConstants.ADMINISTRATIVE_VALIDITY_EXPIRY);
        if (admExp != null) {
            return admExp;
        }
        return getAsDate(SDJWTConstants.EXPIRY_DATE);
    }

    @Override
    public ClaimDate getAdministrativeIssuanceDate() {
        // TODO : PID Rulebook and ETSI both define their own headers, check for conflict ?
        ClaimDate admNbf = getAsDateTime(SDJWTConstants.ADMINISTRATIVE_VALIDITY_NOT_BEFORE);
        if (admNbf != null) {
            return admNbf;
        }
        return getAsDate(SDJWTConstants.ISSUANCE_DATE);
    }

    @Override
    public ClaimString getTrustAnchor() {
        return getAsString(SDJWTConstants.TRUST_ANCHOR);
    }

    @Override
    public ClaimString getResidentAddressStreet() {
        return null;
    }

    @Override
    public ClaimString getResidentAddressHouseNumber() {
        return null;
    }

    @Override
    public ClaimString getIssuingAuthorityRegistrationIdentifier() {
        return getAsString(SDJWTConstants.ISSUING_REGISTRATION_IDENTIFIER);
    }

    @Override
    public ClaimNull getOneTimeUse() {
        /* EAA-5.2.8.2-05: The oneTime claim shall have the null JSON primitive type. */
        return getAsNull(SDJWTConstants.ONE_TIME);
    }

    @Override
    public Claim getShortLived() {
        /* EAA-5.2.12-02: The shortLived claim shall have the null JSON primitive type.  */
        return getAsNull(SDJWTConstants.SHORT_LIVED);
    }

    @Override
    public ClaimArray getEvidence() {
        // TODO : evidence structure is not supported yet (see https://openid.net/specs/openid-ida-verified-claims-1_0.html)
        return getAsArray(SDJWTConstants.EVIDENCE);
    }

    @Override
    public ClaimAttestedAttributesSubject getAttestedAttributesSubject() {
        ClaimMap subAttrs = getAsMap(SDJWTConstants.ATTESTED_ATTRIBUTES_SUBJECT);
        if (subAttrs != null) {
            return new SDJWTClaimAttestedAttributesSubject(subAttrs);
        }
        return null;
    }

}
