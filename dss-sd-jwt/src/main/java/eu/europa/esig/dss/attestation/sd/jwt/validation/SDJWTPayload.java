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
package eu.europa.esig.dss.attestation.sd.jwt.validation;

import eu.europa.esig.dss.attestation.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.attestation.sd.jwt.claim.SDJWTVerifiedClaimAddress;
import eu.europa.esig.dss.attestation.sd.jwt.claim.SDJWTVerifiedClaimAgeOverNNList;
import eu.europa.esig.dss.attestation.sd.jwt.claim.SDJWTVerifiedClaimAttestedAttributesSubject;
import eu.europa.esig.dss.attestation.sd.jwt.claim.SDJWTVerifiedClaimCredentialSubject;
import eu.europa.esig.dss.attestation.sd.jwt.claim.SDJWTVerifiedClaimDeviceKey;
import eu.europa.esig.dss.attestation.sd.jwt.claim.SDJWTVerifiedClaimIntegrity;
import eu.europa.esig.dss.attestation.sd.jwt.claim.SDJWTVerifiedClaimMap;
import eu.europa.esig.dss.attestation.sd.jwt.claim.SDJWTVerifiedClaimPlaceOfBirth;
import eu.europa.esig.dss.attestation.sd.jwt.claim.SDJWTVerifiedClaimStatus;
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
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimNull;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimPlaceOfBirth;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimStatus;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimValidityInfo;
import eu.europa.esig.dss.spi.attestation.AttestationPayload;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class implements a user-friendly access to the attestation payload elements of the SD-JWT token
 *
 */
public class SDJWTPayload extends SDJWTVerifiedClaimMap implements AttestationPayload {

    private static final long serialVersionUID = -4552799683587409954L;

    /**
     * Constructor with a verified payload map, containing the attached disclosures, when applicable
     *
     * @param verifiedPayloadMap {@link String} json payload
     */
    public SDJWTPayload(final VerifiedClaimMap verifiedPayloadMap) {
        super(verifiedPayloadMap.getMapValue());
    }

    @Override
    public VerifiedClaimString getIdentifier() {
        return getAsString(SDJWTConstants.JWT_ID);
    }

    @Override
    public VerifiedClaimString getIssuer() {
        return getAsString(SDJWTConstants.ISSUER);
    }

    @Override
    public VerifiedClaimString getSubject() {
        return getAsString(SDJWTConstants.SUBJECT);
    }

    @Override
    public VerifiedClaimArray getAudience() {
        return getAsArray(SDJWTConstants.AUDIENCE);
    }

    @Override
    public VerifiedClaimDate getIssuedAtTime() {
        return getAsDateTime(SDJWTConstants.ISSUED_AT);
    }

    @Override
    public VerifiedClaimDate getNotBeforeTime() {
        return getAsDateTime(SDJWTConstants.NOT_BEFORE);
    }

    @Override
    public VerifiedClaimDate getExpirationTime() {
        return getAsDateTime(SDJWTConstants.EXPIRATION_TIME);
    }

    @Override
    public VerifiedClaimDate getUpdatedAtTime() {
        return getAsDateTime(SDJWTConstants.UPDATED_AT);
    }

    @Override
    public VerifiedClaimDeviceKey getDeviceKey() {
        VerifiedClaimMap cnf = getAsMap(SDJWTConstants.CNF);
        if (cnf != null) {
            return new SDJWTVerifiedClaimDeviceKey(cnf);
        }
        return null;
    }

    @Override
    public VerifiedClaimString getCategory() {
        VerifiedClaimString category = getAsString(SDJWTConstants.CATEGORY);
        if (category != null) {
            return category;
        }
        return getAsString(SDJWTConstants.ATTESTATION_LEGAL_CATEGORY);
    }

    @Override
    public VerifiedClaimString getVerifiableCredentialsType() {
        return getAsString(SDJWTConstants.VERIFIABLE_CREDENTIALS_TYPE);
    }

    @Override
    public VerifiedClaimIntegrity getVerifiableCredentialsTypeIntegrity() {
        VerifiedClaimString metadataIntegrity = getAsString(SDJWTConstants.VERIFIABLE_CREDENTIALS_INTEGRITY);
        if (metadataIntegrity != null) {
            return new SDJWTVerifiedClaimIntegrity(metadataIntegrity);
        }
        return null;
    }

    @Override
    public VerifiedClaimStatus getStatus() {
        VerifiedClaimMap statusClaim = getAsMap(SDJWTConstants.STATUS);
        if (statusClaim != null) {
            return new SDJWTVerifiedClaimStatus(statusClaim);
        }
        return null;
    }

    @Override
    public VerifiedClaimString getNonce() {
        return getAsString(SDJWTConstants.NONCE);
    }

    @Override
    public VerifiedClaimString getFullName() {
        return getAsString(SDJWTConstants.USER_NAME);
    }

    @Override
    public VerifiedClaimString getGivenName() {
        return getAsString(SDJWTConstants.USER_GIVEN_NAME);
    }

    @Override
    public VerifiedClaimString getFamilyName() {
        return getAsString(SDJWTConstants.USER_FAMILY_NAME);
    }

    @Override
    public VerifiedClaimString getMiddleName() {
        return getAsString(SDJWTConstants.USER_MIDDLE_NAME);
    }

    @Override
    public VerifiedClaimString getNickname() {
        return getAsString(SDJWTConstants.USER_NICKNAME);
    }

    @Override
    public VerifiedClaimString getShortName() {
        return getAsString(SDJWTConstants.USER_PREFERRED_NICKNAME);
    }

    @Override
    public VerifiedClaimString getProfileUrl() {
        return getAsString(SDJWTConstants.USER_PROFILE);
    }

    @Override
    public VerifiedClaimString getPictureUrl() {
        return getAsString(SDJWTConstants.USER_PICTURE);
    }

    @Override
    public VerifiedClaimString getWebsiteUrl() {
        return getAsString(SDJWTConstants.USER_WEBSITE);
    }

    @Override
    public VerifiedClaimString getEmail() {
        return getAsString(SDJWTConstants.USER_EMAIL);
    }

    @Override
    public VerifiedClaimBoolean getEmailVerified() {
        return getAsBoolean(SDJWTConstants.USER_EMAIL_VERIFIED);
    }

    @Override
    public VerifiedClaim getGender() {
        VerifiedClaimString userGender = getAsString(SDJWTConstants.USER_GENDER);
        if (userGender != null) {
            return userGender;
        }
        return getAsNumber(SDJWTConstants.SEX);
    }

    @Override
    public VerifiedClaimDate getBirthdate() {
        return getAsDate(SDJWTConstants.USER_BIRTHDATE);
    }

    @Override
    public VerifiedClaimString getTimezone() {
        return getAsString(SDJWTConstants.USER_ZONEINFO);
    }

    @Override
    public VerifiedClaimString getLocale() {
        return getAsString(SDJWTConstants.USER_LOCALE);
    }

    @Override
    public VerifiedClaimAddress getAddress() {
        VerifiedClaimMap claimAddress = getAsMap(SDJWTConstants.USER_ADDRESS);
        if (claimAddress != null) {
            return new SDJWTVerifiedClaimAddress(claimAddress);
        }
        return null;
    }

    @Override
    public VerifiedClaimString getPhoneNumber() {
        return getAsString(SDJWTConstants.USER_PHONE_NUMBER);
    }

    @Override
    public VerifiedClaimBoolean getPhoneNumberVerified() {
        return getAsBoolean(SDJWTConstants.USER_PHONE_NUMBER_VERIFIED);
    }

    @Override
    public VerifiedClaimPlaceOfBirth getPlaceOfBirth() {
        VerifiedClaimMap claimPlaceOfBirth = getAsMap(SDJWTConstants.USER_PLACE_OF_BIRTH);
        if (claimPlaceOfBirth != null) {
            return new SDJWTVerifiedClaimPlaceOfBirth(claimPlaceOfBirth);
        }
        return null;
    }

    @Override
    public VerifiedClaimArray getNationalities() {
        return getAsArray(SDJWTConstants.USER_NATIONALITIES);
    }

    @Override
    public VerifiedClaimString getBirthGivenName() {
        return getAsString(SDJWTConstants.USER_BIRTH_GIVEN_NAME);
    }

    @Override
    public VerifiedClaimString getBirthFamilyName() {
        return getAsString(SDJWTConstants.USER_BIRTH_FAMILY_NAME);
    }

    @Override
    public VerifiedClaimString getBirthMiddleName() {
        return getAsString(SDJWTConstants.USER_BIRTH_MIDDLE_NAME);
    }

    @Override
    public VerifiedClaimString getSalutation() {
        return getAsString(SDJWTConstants.USER_SALUTATION);
    }

    @Override
    public VerifiedClaimString getTitle() {
        return getAsString(SDJWTConstants.USER_TITLE);
    }

    @Override
    public VerifiedClaimString getMobilePhoneNumber() {
        return getAsString(SDJWTConstants.USER_MOBILE_PHONE_NUMBER);
    }

    @Override
    public VerifiedClaimString getPseudonym() {
        return getAsString(SDJWTConstants.USER_PSEUDONYM);
    }

    @Override
    public List<VerifiedClaimCredentialSubject> getCredentialSubjects() {
        VerifiedClaimMap claimCredentialSubjectAsMap = getAsMap(SDJWTConstants.CREDENTIAL_SUBJECT);
        if (claimCredentialSubjectAsMap != null) {
            return Collections.singletonList(new SDJWTVerifiedClaimCredentialSubject(claimCredentialSubjectAsMap));
        }
        VerifiedClaimArray claimCredentialSubjectAsArray = getAsArray(SDJWTConstants.CREDENTIAL_SUBJECT);
        if (claimCredentialSubjectAsArray != null) {
            List<VerifiedClaimCredentialSubject> result = new ArrayList<>();
            for (VerifiedClaim credentialSubject : claimCredentialSubjectAsArray.getListValue()) {
                if (credentialSubject.isMapValueType()) {
                    result.add(new SDJWTVerifiedClaimCredentialSubject((VerifiedClaimMap) credentialSubject));
                }
            }
            return result;
        }
        return Collections.emptyList();
    }

    @Override
    public VerifiedClaimString getIssuingCountry() {
        return getAsString(SDJWTConstants.ISSUING_COUNTRY);
    }

    @Override
    public VerifiedClaimString getIssuingAuthority() {
        return getAsString(SDJWTConstants.ISSUING_AUTHORITY);
    }

    @Override
    public VerifiedClaimString getDocumentNumber() {
        return getAsString(SDJWTConstants.DOCUMENT_NUMBER);
    }

    @Override
    public VerifiedClaimByteString getPortrait() {
        return null;
    }

    @Override
    public VerifiedClaimDrivingPrivileges getDrivingPrivileges() {
        return null;
    }

    @Override
    public VerifiedClaimString getUNDistinguishingSign() {
        return null;
    }

    @Override
    public VerifiedClaimString getPersonalAdministrativeNumber() {
        return getAsString(SDJWTConstants.PERSONAL_ADMINISTRATIVE_NUMBER);
    }

    @Override
    public VerifiedClaimNumber getHeight() {
        return null;
    }

    @Override
    public VerifiedClaimNumber getWeight() {
        return null;
    }

    @Override
    public VerifiedClaimString getEyeColour() {
        return null;
    }

    @Override
    public VerifiedClaimString getHairColour() {
        return null;
    }

    @Override
    public VerifiedClaimString getPostalAddress() {
        return null;
    }

    @Override
    public VerifiedClaimDate getPortraitCaptureDate() {
        return null;
    }

    @Override
    public VerifiedClaimNumber getAgeInYears() {
        return getAsNumber(SDJWTConstants.AGE_IN_YEARS);
    }

    @Override
    public VerifiedClaimNumber getAgeBirthYear() {
        return getAsNumber(SDJWTConstants.AGE_BIRTH_YEAR);
    }

    @Override
    public VerifiedClaimAgeEqualOrOver getAgeEqualOrOver() {
        VerifiedClaimMap ageEqualOrOver = getAsMap(SDJWTConstants.AGE_EQUAL_OR_OVER);
        if (ageEqualOrOver != null) {
            return new SDJWTVerifiedClaimAgeOverNNList(ageEqualOrOver);
        }
        return null;
    }

    @Override
    public List<VerifiedClaimAgeOverNN> getAgeOverNN() {
        return Collections.emptyList();
    }

    @Override
    public VerifiedClaimString getIssuingJurisdiction() {
        return getAsString(SDJWTConstants.ISSUING_JURISDICTION);
    }

    @Override
    public VerifiedClaimString getResidentAddressCity() {
        return null;
    }

    @Override
    public VerifiedClaimString getResidentAddressState() {
        return null;
    }

    @Override
    public VerifiedClaimString getResidentAddressPostalCode() {
        return null;
    }

    @Override
    public VerifiedClaimString getResidentAddressCountry() {
        return null;
    }

    @Override
    public List<VerifiedClaimBiometricTemplateXX> getBiometricTemplate() {
        return Collections.emptyList();
    }

    @Override
    public VerifiedClaimByteString getSignatureUsualMark() {
        return null;
    }

    @Override
    public VerifiedClaimString getVersion() {
        return null;
    }

    @Override
    public VerifiedClaimString getDocType() {
        return null;
    }

    @Override
    public VerifiedClaimValidityInfo getValidityInfo() {
        return null;
    }

    @Override
    public VerifiedClaimByteString getFingerprint() {
        return null;
    }

    @Override
    public VerifiedClaimString getBusinessName() {
        return null;
    }

    @Override
    public VerifiedClaimString getOrganizationName() {
        return null;
    }

    @Override
    public VerifiedClaimString getBirthFullName() {
        return null;
    }

    @Override
    public VerifiedClaimString getProfession() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipFather() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipMother() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipParent() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipSon() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipDaughter() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipBrother() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipSister() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipSibling() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipSpouse() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipFatherInLaw() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipMotherInLaw() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipParentInLaw() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipSonInLaw() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipDaughterInLaw() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipChildInLaw() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipParentalAuthority() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipLegalRepresentative() {
        return null;
    }

    @Override
    public VerifiedClaimString getRelationshipAgent() {
        return null;
    }

    @Override
    public VerifiedClaimString getDocumentType() {
        return null;
    }

    @Override
    public VerifiedClaimDate getAdministrativeExpirationDate() {
        // TODO : PID Rulebook and ETSI both define their own headers, check for conflict ?
        VerifiedClaimDate admExp = getAsDateTime(SDJWTConstants.ADMINISTRATIVE_VALIDITY_EXPIRY);
        if (admExp != null) {
            return admExp;
        }
        return getAsDate(SDJWTConstants.EXPIRY_DATE);
    }

    @Override
    public VerifiedClaimDate getAdministrativeIssuanceDate() {
        // TODO : PID Rulebook and ETSI both define their own headers, check for conflict ?
        VerifiedClaimDate admNbf = getAsDateTime(SDJWTConstants.ADMINISTRATIVE_VALIDITY_NOT_BEFORE);
        if (admNbf != null) {
            return admNbf;
        }
        return getAsDate(SDJWTConstants.ISSUANCE_DATE);
    }

    @Override
    public VerifiedClaimString getTrustAnchor() {
        return getAsString(SDJWTConstants.TRUST_ANCHOR);
    }

    @Override
    public VerifiedClaimString getResidentAddressStreet() {
        return null;
    }

    @Override
    public VerifiedClaimString getResidentAddressHouseNumber() {
        return null;
    }

    @Override
    public VerifiedClaimString getIssuingAuthorityRegistrationIdentifier() {
        return getAsString(SDJWTConstants.ISSUING_REGISTRATION_IDENTIFIER);
    }

    @Override
    public VerifiedClaimNull getOneTimeUse() {
        /* EAA-5.2.8.2-05: The oneTime claim shall have the null JSON primitive type. */
        return getAsNull(SDJWTConstants.ONE_TIME);
    }

    @Override
    public VerifiedClaim getShortLived() {
        /* EAA-5.2.12-02: The shortLived claim shall have the null JSON primitive type.  */
        return getAsNull(SDJWTConstants.SHORT_LIVED);
    }

    @Override
    public VerifiedClaimArray getEvidence() {
        // TODO : evidence structure is not supported yet (see https://openid.net/specs/openid-ida-verified-claims-1_0.html)
        return getAsArray(SDJWTConstants.EVIDENCE);
    }

    @Override
    public VerifiedClaimAttestedAttributesSubject getAttestedAttributesSubject() {
        VerifiedClaimMap subAttrs = getAsMap(SDJWTConstants.ATTESTED_ATTRIBUTES_SUBJECT);
        if (subAttrs != null) {
            return new SDJWTVerifiedClaimAttestedAttributesSubject(subAttrs);
        }
        return null;
    }

}
