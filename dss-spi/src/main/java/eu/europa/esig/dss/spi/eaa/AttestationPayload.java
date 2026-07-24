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
package eu.europa.esig.dss.spi.eaa;

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
import eu.europa.esig.dss.model.eaa.claim.ClaimNumber;
import eu.europa.esig.dss.model.eaa.claim.ClaimStatus;
import eu.europa.esig.dss.model.eaa.claim.ClaimString;
import eu.europa.esig.dss.model.eaa.claim.ClaimValidityInfo;

import java.util.List;

/**
 * Provides an interface for accessing the content of the EAA payload
 */
public interface AttestationPayload extends Claim {

    /**
     * Gets the EAA's unique identifier, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getIdentifier();

    /**
     * Gets the EAA's issuer, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getIssuer();

    /**
     * Gets the EAA's subject, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getSubject();

    /**
     * Gets the list of recipients the EAA is intended for, when present
     *
     * @return {@link ClaimArray}
     */
    ClaimArray getAudience();

    /**
     * Gets the time at which the EAA was issued, when present
     *
     * @return {@link ClaimDate}
     */
    ClaimDate getIssuedAtTime();

    /**
     * Gets the time before which the EAA is not accepted for processing, when present
     *
     * @return {@link ClaimDate}
     */
    ClaimDate getNotBeforeTime();

    /**
     * Gets the expiration time of the EAA, after which the EAA is not accepted for processing, when present
     *
     * @return {@link ClaimDate}
     */
    ClaimDate getExpirationTime();

    /**
     * Gets the time at which the information present within the EAA was the last time updated, when present
     *
     * @return {@link ClaimDate}
     */
    ClaimDate getUpdatedAtTime();

    /**
     * Gets the wallet holder's key
     *
     * @return {@link ClaimDeviceKey}
     */
    ClaimDeviceKey getDeviceKey();

    /**
     * Gets the EAA category URN, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getCategory();

    /**
     * Gets the EAA's Metadata type, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getVerifiableCredentialsType();

    /**
     * Gets the EAA's Metadata integrity claim, when present
     *
     * @return {@link Claim}
     */
    ClaimIntegrity getVerifiableCredentialsTypeIntegrity();

    /**
     * Gets the EAA's Status value, when present
     *
     * @return {@link ClaimStatus}
     */
    ClaimStatus getStatus();

    /**
     * Gets the EAA's nonce value, used to associate the Client's session Id with the EAA, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getNonce();

    /**
     * Gets the user's full name information, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getFullName();

    /**
     * Gets the user's first or given name information, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getGivenName();

    /**
     * Gets the user's last name or surname information, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getFamilyName();

    /**
     * Gets the user's middle name information, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getMiddleName();

    /**
     * Gets the user's casual name information, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getNickname();

    /**
     * Gets the user's preferred name, usually a shorthand name, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getShortName();

    /**
     * Gets the user's profile page URL, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getProfileUrl();

    /**
     * Gets the user's profile picture URL, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getPictureUrl();

    /**
     * Gets the user's website or blog URL, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getWebsiteUrl();

    /**
     * Gets the user's preferred email address, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getEmail();

    /**
     * Gets whether the user's email address has been verified, when present
     *
     * @return {@link ClaimBoolean}
     */
    ClaimBoolean getEmailVerified();

    /**
     * Gets the user's gender, when present
     *
     * @return {@link ClaimString}
     */
    Claim getGender();

    /**
     * Gets the user's birthdate, when present
     *
     * @return {@link Claim}
     */
    Claim getBirthdate();

    /**
     * Gets the user's TimeZone, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getTimezone();

    /**
     * Gets the user's locale, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getLocale();

    /**
     * Gets the user's full postal or physical address, when present
     *
     * @return {@link ClaimString}
     */
    ClaimAddress getAddress();

    /**
     * Gets the user's preferred telephone number, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getPhoneNumber();

    /**
     * Gets whether the user's preferred telephone number has been verified, when present
     *
     * @return {@link ClaimBoolean}
     */
    ClaimBoolean getPhoneNumberVerified();

    /**
     * Gets user's place of birth, when present
     *
     * @return {@link Claim}
     */
    Claim getPlaceOfBirth();

    /**
     * Gets user's nationalities using ICAO 3-letter codes, when present
     *
     * @return {@link Claim}
     */
    Claim getNationalities();

    /**
     * Gets user's first or given name when they were born, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getBirthGivenName();

    /**
     * Gets user's family or last name when they were born, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getBirthFamilyName();

    /**
     * Gets user's middle name when they were born, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getBirthMiddleName();

    /**
     * Gets user's salutation, e.g., "Mr", when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getSalutation();

    /**
     * Gets user's title, e.g., "Dr", when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getTitle();

    /**
     * Gets user's mobile phone number, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getMobilePhoneNumber();

    /**
     * Gets user's stage name, religious name or any other type of alias/pseudonym, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getPseudonym();

    /**
     * Returns a list of "4.8 Credential Subject" claims defined in W3C Verifiable Credentials Data Model v2.0.
     *
     * @return a list of {@link ClaimCredentialSubject}s
     */
    List<ClaimCredentialSubject> getCredentialSubjects();

    /* Mdoc specific payload headers as per ISO/IEC 18013-5 */

    /**
     * Gets alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory
     *
     * @return {@link ClaimString}
     */
    ClaimString getIssuingCountry();

    /**
     * Gets issuing authority name.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimString}
     */
    ClaimString getIssuingAuthority();

    /**
     * Gets the number assigned or calculated by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimString}
     */
    ClaimString getDocumentNumber();

    /**
     * Gets a reproduction of the mDL holder’s portrait.
     *
     * @return {@link ClaimByteString}
     */
    ClaimByteString getPortrait();

    /**
     * Gets driving privileges of the mDL holder.
     *
     * @return {@link ClaimByteString}
     */
    ClaimDrivingPrivileges getDrivingPrivileges();

    /**
     * Gets the distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F.
     * If no applicable distinguishing sign is available in ISO/IEC 18013-1, an IA may
     * use an empty identifier or another identifier by which it is internationally recognized.
     * In this case the IA should ensure there is no collision with other IA’s.
     *
     * @return {@link ClaimString}
     */
    ClaimString getUNDistinguishingSign();

    /**
     * An audit control number assigned by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimString}
     */
    ClaimString getPersonalAdministrativeNumber();

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link ClaimNumber}
     */
    ClaimNumber getHeight();

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link ClaimNumber}
     */
    ClaimNumber getWeight();

    /**
     * Gets the mDL holder’s eye colour. The value shall be one of the following: “black”, “blue”,
     * “brown”, “dichromatic”, “grey”, “green”, “hazel”, “maroon”, “pink”, “unknown”.
     *
     * @return {@link ClaimNumber}
     */
    ClaimString getEyeColour();

    /**
     * Gets the mDL holder’s hair colour. The value shall be one of the following: “bald”, “black”,
     * “blond”, “brown”, “grey”, “red”, “auburn”, “sandy”, “white”, “unknown”.
     *
     * @return {@link ClaimNumber}
     */
    ClaimString getHairColour();

    /**
     * Gets the place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.).
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimNumber}
     */
    ClaimString getPostalAddress();

    /**
     * Gets the date when portrait was taken.
     *
     * @return {@link ClaimNumber}
     */
    ClaimDate getPortraitCaptureDate();

    /**
     * Gets the date the age of the mDL holder
     *
     * @return {@link ClaimNumber}
     */
    ClaimNumber getAgeInYears();

    /**
     * Gets the year when the mDL holder was born
     *
     * @return {@link ClaimNumber}
     */
    ClaimNumber getAgeBirthYear();

    /**
     * Gets a map of elements attesting whether the User to whom the person identification data relates is
     * at least NN years old. N &lt;&gt; 18. Multiple instances of this attribute may be present, provided the value of
     * NN is different in each of them. If present, the requirements in clause 7.2.5 of ISO/IEC 18013-5 are
     * applicable for these attributes.
     *
     * @return {@link ClaimAgeEqualOrOver}
     */
    ClaimAgeEqualOrOver getAgeEqualOrOver();

    /**
     * Gets a list of elements is used to convey to an mDL verifier, in a data-minimized fashion, if the mDL holder
     * is as old or older than a specified age, or if the mDL holder is younger than a specified age. To achieve
     * this, the mDL contains age attestation identifiers. An age attestation identifier has the format age_over_
     * NN where NN is a value from 00 to 99. The value of an age attestation identifier can be TRUE or FALSE.
     *
     * @return a list of {@link ClaimAgeOverNN}s
     */
    List<ClaimAgeOverNN> getAgeOverNN();

    /**
     * Gets a country subdivision code of the jurisdiction that issued the mDL as defined in
     * ISO 3166-2:2020, Clause 8. The first part of the code shall be the same as the value for issuing_country.
     *
     * @return {@link ClaimString}
     */
     ClaimString getIssuingJurisdiction();

    /**
     * Gets the city where the mDL holder lives. The value shall only use latin1 characters
     * and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimString}
     */
    ClaimString getResidentAddressCity();

    /**
     * Gets the state/province/district where the mDL holder lives.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimString}
     */
    ClaimString getResidentAddressState();

    /**
     * Gets the postal code of the mDL holder. The value shall only use latin1b characters
     * and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimString}
     */
    ClaimString getResidentAddressPostalCode();

    /**
     * Gets the country where the mDL holder lives as a two letter country code (alpha-2 code)
     * defined in ISO 3166-1.
     *
     * @return {@link ClaimString}
     */
    ClaimString getResidentAddressCountry();

    /**
     * Gets a list of elements contains optional facial, fingerprint, iris, or other biometric information of the mDL
     * holder.
     * A biometric template identifier has the format biometric_template_xx
     * where xx shall be replaced with the corresponding “Abstract value name” found in ISO/IEC 19785
     * 3:2020, Table 7, according to the following convention: capitalized characters are replaced with their
     * lowercase equivalent and spaces or non-alphanumeric characters are replaced by underscores (_).
     *
     * @return a list of {@link ClaimBiometricTemplateXX}s
     */
    List<ClaimBiometricTemplateXX> getBiometricTemplate();

    /**
     * Gets an image of the signature or usual mark of the mDL holder, see 7.2.7 ISO/IEC 18013-5.
     *
     * @return {@link ClaimByteString}
     */
    ClaimByteString getSignatureUsualMark();

    /* "9.1.2.4 Signing method and structure for MSO" headers as per ISO/IEC 18013-5 */

    /**
     * Gets a version of the MobileSecurityObject.
     *
     * @return {@link ClaimString}
     */
    ClaimString getVersion();

    /**
     * Gets a docType as used in Documents.
     * NOTE: This a mandatory non-disclosable property in comparison with {@code #getDocumentType}.
     *
     * @return {@link ClaimString}
     */
    ClaimString getDocType();

    /**
     * Gets the information related to the validity of the MSO and its signature.
     *
     * @return {@link ClaimString}
     */
    ClaimValidityInfo getValidityInfo();

    /* Mdoc specific payload headers as per ISO/IEC 23220-2 */

    /**
     * Gets a reproduction of the holder’s fingerprint data (TBC).
     *
     * @return {@link ClaimByteString}
     */
    ClaimByteString getFingerprint();

    /**
     * Gets a business name of the holder.
     *
     * @return {@link ClaimString}
     */
    ClaimString getBusinessName();

    /**
     * Gets a name of legal person.
     *
     * @return {@link ClaimString}
     */
    ClaimString getOrganizationName();

    /**
     * Gets the name(s) which holder was born.
     *
     * @return {@link ClaimString}
     */
    ClaimString getBirthFullName();

    /**
     * Gets the profession of the holder.
     *
     * @return {@link ClaimString}
     */
    ClaimString getProfession();

    /* "6.3.2.3 Relationship attributes" headers as per ISO/IEC 23220-2 */

    /**
     * Gets the father of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipFather();

    /**
     * Gets the mother of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipMother();

    /**
     * Gets the parent of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipParent();

    /**
     * Gets the son of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipSon();

    /**
     * Gets the daughter of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipDaughter();

    /**
     * Gets the brother of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipBrother();

    /**
     * Gets the sister of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipSister();

    /**
     * Gets the sibling of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipSibling();

    /**
     * Gets the spouse of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipSpouse();

    /**
     * Gets the father-in-law of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipFatherInLaw();

    /**
     * Gets the mother-in-law of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipMotherInLaw();

    /**
     * Gets the parent-in-law of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipParentInLaw();

    /**
     * Gets the son-in-law of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipSonInLaw();

    /**
     * Gets the daughter-in-law of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipDaughterInLaw();

    /**
     * Gets the child-in-law of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipChildInLaw();

    /**
     * Gets the parental authority of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipParentalAuthority();

    /**
     * Gets the legal representative of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipLegalRepresentative();

    /**
     * Gets the voluntary agent of the holder
     *
     * @return {@link ClaimString}
     */
    ClaimString getRelationshipAgent();

    /* "6.3.4 Data elements for document entity" headers as per ISO/IEC 23220-2 */

    /**
     * Gets the document type.
     * NOTE: This a selectively disclosable property in comparison with {@code #getDocType}.
     *
     * @return {@link ClaimString}
     */
    ClaimString getDocumentType();

    /* ARF PID Rulebook headers */

    /**
     * Gets the date when the data (e.g. a PID) was issued
     *
     * @return {@link ClaimDate}
     */
    ClaimDate getAdministrativeIssuanceDate();

    /**
     * Gets the date when the data (e.g. a PID) will expire
     *
     * @return {@link ClaimDate}
     */
    ClaimDate getAdministrativeExpirationDate();

    /**
     * Gets the URL at which a machine-readable version of the trust anchor to be used for
     * verifying the PID can be found or looked up.
     *
     * @return {@link ClaimString}
     */
    ClaimString getTrustAnchor();

    /**
     * Gets the name of the street where the user to whom the person identification data relates currently resides.
     *
     * @return {@link ClaimString}
     */
    ClaimString getResidentAddressStreet();

    /**
     * Gets the house number where the user to whom the person identification data relates currently resides,
     * including any affix or suffix.
     *
     * @return {@link ClaimString}
     */
    ClaimString getResidentAddressHouseNumber();

    /* ETSI TS 119 472-1 "5 Implementation of EAA based on SD-JWT VC" header parameters */

    /**
     * Gets the registration identifier of the legal entity on whose behalf the EAA has been issued.
     *
     * @return {@link ClaimString}
     */
    ClaimString getIssuingAuthorityRegistrationIdentifier();

    /**
     * Gets the signal indicating that the EAA shall be used only once, and that it shall not be retained for future use.
     *
     * @return {@link Claim}
     */
    Claim getOneTimeUse();

    /**
     * Gets the EAA short-lived component indicating that the validity period of the EAA is so short that
     * it shall not be necessary to check its revocation status.
     *
     * @return {@link Claim}
     */
    Claim getShortLived();

    /**
     * Gets the array of evidence elements.
     *
     * @return {@link Claim}
     */
    ClaimArray getEvidence();

    /**
     * Gets the claim for associating a set of attributes to one entity different than the EAA subject.
     *
     * @return {@link Claim}
     */
    ClaimAttestedAttributesSubject getAttestedAttributesSubject();

}
