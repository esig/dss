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
package eu.europa.esig.dss.spi.attestation;

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
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimStatus;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimValidityInfo;

import java.util.List;

/**
 * Provides an interface for accessing the content of the attestation payload
 */
public interface AttestationPayload extends VerifiedClaim {

    /**
     * Gets the attestation's unique identifier, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getIdentifier();

    /**
     * Gets the attestation's issuer, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getIssuer();

    /**
     * Gets the attestation's subject, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getSubject();

    /**
     * Gets the list of recipients the attestation is intended for, when present
     *
     * @return {@link VerifiedClaimArray}
     */
    VerifiedClaimArray getAudience();

    /**
     * Gets the time at which the attestation was issued, when present
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getIssuedAtTime();

    /**
     * Gets the time before which the attestation is not accepted for processing, when present
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getNotBeforeTime();

    /**
     * Gets the expiration time of the attestation, after which the attestation is not accepted for processing, when present
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getExpirationTime();

    /**
     * Gets the time at which the information present within the attestation was the last time updated, when present
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getUpdatedAtTime();

    /**
     * Gets the wallet holder's key
     *
     * @return {@link VerifiedClaimDeviceKey}
     */
    VerifiedClaimDeviceKey getDeviceKey();

    /**
     * Gets the attestation category URN, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getCategory();

    /**
     * Gets the attestation's Metadata type, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getVerifiableCredentialsType();

    /**
     * Gets the attestation's Metadata integrity claim, when present
     *
     * @return {@link VerifiedClaim}
     */
    VerifiedClaimIntegrity getVerifiableCredentialsTypeIntegrity();

    /**
     * Gets the attestation's Status value, when present
     *
     * @return {@link VerifiedClaimStatus}
     */
    VerifiedClaimStatus getStatus();

    /**
     * Gets the attestation's nonce value, used to associate the Client's session Id with the attestation, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getNonce();

    /**
     * Gets the user's full name information, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getFullName();

    /**
     * Gets the user's first or given name information, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getGivenName();

    /**
     * Gets the user's last name or surname information, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getFamilyName();

    /**
     * Gets the user's middle name information, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getMiddleName();

    /**
     * Gets the user's casual name information, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getNickname();

    /**
     * Gets the user's preferred name, usually a shorthand name, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getShortName();

    /**
     * Gets the user's profile page URL, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getProfileUrl();

    /**
     * Gets the user's profile picture URL, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getPictureUrl();

    /**
     * Gets the user's website or blog URL, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getWebsiteUrl();

    /**
     * Gets the user's preferred email address, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getEmail();

    /**
     * Gets whether the user's email address has been verified, when present
     *
     * @return {@link VerifiedClaimBoolean}
     */
    VerifiedClaimBoolean getEmailVerified();

    /**
     * Gets the user's gender, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaim getGender();

    /**
     * Gets the user's birthdate, when present
     *
     * @return {@link VerifiedClaim}
     */
    VerifiedClaim getBirthdate();

    /**
     * Gets the user's TimeZone, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getTimezone();

    /**
     * Gets the user's locale, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getLocale();

    /**
     * Gets the user's full postal or physical address, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimAddress getAddress();

    /**
     * Gets the user's preferred telephone number, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getPhoneNumber();

    /**
     * Gets whether the user's preferred telephone number has been verified, when present
     *
     * @return {@link VerifiedClaimBoolean}
     */
    VerifiedClaimBoolean getPhoneNumberVerified();

    /**
     * Gets user's place of birth, when present
     *
     * @return {@link VerifiedClaim}
     */
    VerifiedClaim getPlaceOfBirth();

    /**
     * Gets user's nationalities using ICAO 3-letter codes, when present
     *
     * @return {@link VerifiedClaim}
     */
    VerifiedClaim getNationalities();

    /**
     * Gets user's first or given name when they were born, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getBirthGivenName();

    /**
     * Gets user's family or last name when they were born, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getBirthFamilyName();

    /**
     * Gets user's middle name when they were born, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getBirthMiddleName();

    /**
     * Gets user's salutation, e.g., "Mr", when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getSalutation();

    /**
     * Gets user's title, e.g., "Dr", when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getTitle();

    /**
     * Gets user's mobile phone number, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getMobilePhoneNumber();

    /**
     * Gets user's stage name, religious name or any other type of alias/pseudonym, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getPseudonym();

    /**
     * Returns a list of "4.8 Credential Subject" claims defined in W3C Verifiable Credentials Data Model v2.0.
     *
     * @return a list of {@link VerifiedClaimCredentialSubject}s
     */
    List<VerifiedClaimCredentialSubject> getCredentialSubjects();

    /* Mdoc specific payload headers as per ISO/IEC 18013-5 */

    /**
     * Gets alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getIssuingCountry();

    /**
     * Gets issuing authority name.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getIssuingAuthority();

    /**
     * Gets the number assigned or calculated by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getDocumentNumber();

    /**
     * Gets a reproduction of the mDL holder’s portrait.
     *
     * @return {@link VerifiedClaimByteString}
     */
    VerifiedClaimByteString getPortrait();

    /**
     * Gets driving privileges of the mDL holder.
     *
     * @return {@link VerifiedClaimByteString}
     */
    VerifiedClaimDrivingPrivileges getDrivingPrivileges();

    /**
     * Gets the distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F.
     * If no applicable distinguishing sign is available in ISO/IEC 18013-1, an IA may
     * use an empty identifier or another identifier by which it is internationally recognized.
     * In this case the IA should ensure there is no collision with other IA’s.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getUNDistinguishingSign();

    /**
     * An audit control number assigned by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getPersonalAdministrativeNumber();

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link VerifiedClaimNumber}
     */
    VerifiedClaimNumber getHeight();

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link VerifiedClaimNumber}
     */
    VerifiedClaimNumber getWeight();

    /**
     * Gets the mDL holder’s eye colour. The value shall be one of the following: “black”, “blue”,
     * “brown”, “dichromatic”, “grey”, “green”, “hazel”, “maroon”, “pink”, “unknown”.
     *
     * @return {@link VerifiedClaimNumber}
     */
    VerifiedClaimString getEyeColour();

    /**
     * Gets the mDL holder’s hair colour. The value shall be one of the following: “bald”, “black”,
     * “blond”, “brown”, “grey”, “red”, “auburn”, “sandy”, “white”, “unknown”.
     *
     * @return {@link VerifiedClaimNumber}
     */
    VerifiedClaimString getHairColour();

    /**
     * Gets the place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.).
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link VerifiedClaimNumber}
     */
    VerifiedClaimString getPostalAddress();

    /**
     * Gets the date when portrait was taken.
     *
     * @return {@link VerifiedClaimNumber}
     */
    VerifiedClaimDate getPortraitCaptureDate();

    /**
     * Gets the date the age of the mDL holder
     *
     * @return {@link VerifiedClaimNumber}
     */
    VerifiedClaimNumber getAgeInYears();

    /**
     * Gets the year when the mDL holder was born
     *
     * @return {@link VerifiedClaimNumber}
     */
    VerifiedClaimNumber getAgeBirthYear();

    /**
     * Gets a map of elements attesting whether the User to whom the person identification data relates is
     * at least NN years old. N &lt;&gt; 18. Multiple instances of this attribute may be present, provided the value of
     * NN is different in each of them. If present, the requirements in clause 7.2.5 of ISO/IEC 18013-5 are
     * applicable for these attributes.
     *
     * @return {@link VerifiedClaimAgeEqualOrOver}
     */
    VerifiedClaimAgeEqualOrOver getAgeEqualOrOver();

    /**
     * Gets a list of elements is used to convey to an mDL verifier, in a data-minimized fashion, if the mDL holder
     * is as old or older than a specified age, or if the mDL holder is younger than a specified age. To achieve
     * this, the mDL contains age attestation identifiers. An age attestation identifier has the format age_over_
     * NN where NN is a value from 00 to 99. The value of an age attestation identifier can be TRUE or FALSE.
     *
     * @return a list of {@link VerifiedClaimAgeOverNN}s
     */
    List<VerifiedClaimAgeOverNN> getAgeOverNN();

    /**
     * Gets a country subdivision code of the jurisdiction that issued the mDL as defined in
     * ISO 3166-2:2020, Clause 8. The first part of the code shall be the same as the value for issuing_country.
     *
     * @return {@link VerifiedClaimString}
     */
     VerifiedClaimString getIssuingJurisdiction();

    /**
     * Gets the city where the mDL holder lives. The value shall only use latin1 characters
     * and shall have a maximum length of 150 characters.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getResidentAddressCity();

    /**
     * Gets the state/province/district where the mDL holder lives.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getResidentAddressState();

    /**
     * Gets the postal code of the mDL holder. The value shall only use latin1b characters
     * and shall have a maximum length of 150 characters.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getResidentAddressPostalCode();

    /**
     * Gets the country where the mDL holder lives as a two letter country code (alpha-2 code)
     * defined in ISO 3166-1.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getResidentAddressCountry();

    /**
     * Gets a list of elements contains optional facial, fingerprint, iris, or other biometric information of the mDL
     * holder.
     * A biometric template identifier has the format biometric_template_xx
     * where xx shall be replaced with the corresponding “Abstract value name” found in ISO/IEC 19785
     * 3:2020, Table 7, according to the following convention: capitalized characters are replaced with their
     * lowercase equivalent and spaces or non-alphanumeric characters are replaced by underscores (_).
     *
     * @return a list of {@link VerifiedClaimBiometricTemplateXX}s
     */
    List<VerifiedClaimBiometricTemplateXX> getBiometricTemplate();

    /**
     * Gets an image of the signature or usual mark of the mDL holder, see 7.2.7 ISO/IEC 18013-5.
     *
     * @return {@link VerifiedClaimByteString}
     */
    VerifiedClaimByteString getSignatureUsualMark();

    /* "9.1.2.4 Signing method and structure for MSO" headers as per ISO/IEC 18013-5 */

    /**
     * Gets a version of the MobileSecurityObject.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getVersion();

    /**
     * Gets a docType as used in Documents.
     * NOTE: This a mandatory non-disclosable property in comparison with {@code #getDocumentType}.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getDocType();

    /**
     * Gets the information related to the validity of the MSO and its signature.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimValidityInfo getValidityInfo();

    /* Mdoc specific payload headers as per ISO/IEC 23220-2 */

    /**
     * Gets a reproduction of the holder’s fingerprint data (TBC).
     *
     * @return {@link VerifiedClaimByteString}
     */
    VerifiedClaimByteString getFingerprint();

    /**
     * Gets a business name of the holder.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getBusinessName();

    /**
     * Gets a name of legal person.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getOrganizationName();

    /**
     * Gets the name(s) which holder was born.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getBirthFullName();

    /**
     * Gets the profession of the holder.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getProfession();

    /* "6.3.2.3 Relationship attributes" headers as per ISO/IEC 23220-2 */

    /**
     * Gets the father of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipFather();

    /**
     * Gets the mother of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipMother();

    /**
     * Gets the parent of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipParent();

    /**
     * Gets the son of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipSon();

    /**
     * Gets the daughter of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipDaughter();

    /**
     * Gets the brother of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipBrother();

    /**
     * Gets the sister of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipSister();

    /**
     * Gets the sibling of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipSibling();

    /**
     * Gets the spouse of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipSpouse();

    /**
     * Gets the father-in-law of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipFatherInLaw();

    /**
     * Gets the mother-in-law of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipMotherInLaw();

    /**
     * Gets the parent-in-law of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipParentInLaw();

    /**
     * Gets the son-in-law of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipSonInLaw();

    /**
     * Gets the daughter-in-law of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipDaughterInLaw();

    /**
     * Gets the child-in-law of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipChildInLaw();

    /**
     * Gets the parental authority of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipParentalAuthority();

    /**
     * Gets the legal representative of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipLegalRepresentative();

    /**
     * Gets the voluntary agent of the holder
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getRelationshipAgent();

    /* "6.3.4 Data elements for document entity" headers as per ISO/IEC 23220-2 */

    /**
     * Gets the document type.
     * NOTE: This a selectively disclosable property in comparison with {@code #getDocType}.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getDocumentType();

    /* ARF PID Rulebook headers */

    /**
     * Gets the date when the data (e.g. a PID) was issued
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getAdministrativeIssuanceDate();

    /**
     * Gets the date when the data (e.g. a PID) will expire
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getAdministrativeExpirationDate();

    /**
     * Gets the URL at which a machine-readable version of the trust anchor to be used for
     * verifying the PID can be found or looked up.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getTrustAnchor();

    /**
     * Gets the name of the street where the user to whom the person identification data relates currently resides.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getResidentAddressStreet();

    /**
     * Gets the house number where the user to whom the person identification data relates currently resides,
     * including any affix or suffix.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getResidentAddressHouseNumber();

    /* ETSI TS 119 472-1 "5 Implementation of attestation based on SD-JWT VC" header parameters */

    /**
     * Gets the registration identifier of the legal entity on whose behalf the attestation has been issued.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getIssuingAuthorityRegistrationIdentifier();

    /**
     * Gets the signal indicating that the attestation shall be used only once, and that it shall not be retained for future use.
     *
     * @return {@link VerifiedClaim}
     */
    VerifiedClaim getOneTimeUse();

    /**
     * Gets the attestation short-lived component indicating that the validity period of the attestation is so short that
     * it shall not be necessary to check its revocation status.
     *
     * @return {@link VerifiedClaim}
     */
    VerifiedClaim getShortLived();

    /**
     * Gets the array of evidence elements.
     *
     * @return {@link VerifiedClaim}
     */
    VerifiedClaimArray getEvidence();

    /**
     * Gets the claim for associating a set of attributes to one entity different than the attestation subject.
     *
     * @return {@link VerifiedClaim}
     */
    VerifiedClaimAttestedAttributesSubject getAttestedAttributesSubject();

}
