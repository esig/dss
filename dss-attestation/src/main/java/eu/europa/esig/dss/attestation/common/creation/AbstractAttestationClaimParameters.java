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
package eu.europa.esig.dss.attestation.common.creation;

import eu.europa.esig.dss.attestation.common.creation.claim.AttestationClaim;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Contains common parameters used within SD-JWT VC and mdoc implementations
 *
 * @param <C> implementation of {@link AttestationClaim} for the EAA format
 */
public abstract class AbstractAttestationClaimParameters<C extends AttestationClaim> implements AttestationClaimParameters<C> {

    /**
     * Date of the issuance of digital credentials
     */
    private Date issuanceDate;

    /* OpenID Connect Core 1.0 */

    /**
     * The user's first or given name information
     */
    private String givenName;

    /**
     * The user's last name or surname information
     */
    private String familyName;

    /**
     * The user's birthdate
     */
    private Date birthdate;

    /**
     * User's nationalities using ICAO 3-letter codes
     */
    private List<String> nationalities;

    /**
     * The user's preferred email address
     */
    private String email;

    /**
     * The user's preferred telephone number
     */
    private String phoneNumber;

    /* Address */

    /**
     * The place where the mDL holder resides and/or may be contacted
     */
    private String postalAddress;

    /**
     * The house number where the user currently resides
     */
    private String addressHouseNumber;

    /**
     * The name of the street where the user currently resides
     */
    private String addressStreet;

    /**
     * The city where the user currently resides
     */
    private String addressCity;

    /**
     * The state/province/district where the user currently resides
     */
    private String addressState;

    /**
     * The postal code where the user currently resides
     */
    private String addressPostalCode;

    /**
     * The country where the user currently resides
     */
    private String addressCountry;

    /* OpenID Connect for Identity Assurance Claims Registration 1.0 */

    /**
     * User's place of birth country (PID Rulebook)
     */
    private String placeOfBirthCountry;

    /**
     * User's place of birth region (PID Rulebook)
     */
    private String placeOfBirthRegion;

    /**
     * User's place of birth locality (PID Rulebook)
     */
    private String placeOfBirthLocality;

    /**
     * User's first or given name when they were born
     */
    private String birthGivenName;

    /**
     * User's family or last name when they were born
     */
    private String birthFamilyName;

    /**
     * User's title, e.g., "Dr"
     */
    private String title;

    /**
     * User's mobile phone number
     */
    private String mobilePhoneNumber;

    /**
     * User's stage name, religious name or any other type of alias/pseudonym
     */
    private String pseudonym;

    /* PID Rulebook claims */

    /**
     * An audit control number assigned by the issuing authority
     */
    private String personalAdministrativeNumber;

    /**
     * The user's gender
     */
    private Integer sex;

    /**
     * Alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory
     */
    private String issuingCountry;

    /**
     * Issuing authority name
     */
    private String issuingAuthority;

    /**
     * Country subdivision code of the jurisdiction that issued the mDL
     */
    private String issuingJurisdiction;

    /**
     * The number assigned or calculated by the issuing authority
     */
    private String documentNumber;

    /**
     * The age of the mDL holder
     */
    private Integer ageInYears;

    /**
     * The year when the mDL holder was born
     */
    private Integer ageBirthYear;

    /**
     * URL at which a machine-readable version of the trust anchor can be found
     */
    private String trustAnchor;

    /**
     * Age attestation identifiers
     */
    private Map<Integer, Boolean> ageOverNN;

    /* ETSI TS 119 472-1 qualified claims */

    /**
     * The registration identifier of the legal entity on whose behalf the EAA has been issued
     */
    private String issuingAuthorityRegistrationIdentifier;

    /**
     * The date when the data (e.g. a PID) was issued
     */
    private Date administrativeIssuanceDate;

    /**
     * The date when the data (e.g. a PID) will expire
     */
    private Date administrativeExpirationDate;

    /**
     * Contains a list of other arbitrary provided claims
     */
    private final List<C> otherClaims = new ArrayList<>();

    /**
     * Default constructor
     */
    protected AbstractAttestationClaimParameters() {
        // empty
    }

    @Override
    public Date getIssuanceDate() {
        return issuanceDate;
    }

    /**
     * Sets the EAA issuance date
     *
     * @param issuanceDate {@link Date}
     */
    public void setIssuanceDate(final Date issuanceDate) {
        this.issuanceDate = issuanceDate;
    }

    @Override
    public String getGivenName() {
        return givenName;
    }

    /**
     * Sets the user's first or given name information
     *
     * @param givenName {@link String}
     */
    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    @Override
    public String getFamilyName() {
        return familyName;
    }

    /**
     * Sets the user's last name or surname information
     *
     * @param familyName {@link String}
     */
    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    @Override
    public String getEmail() {
        return email;
    }

    /**
     * Sets the user's preferred email address
     *
     * @param email {@link String}
     */
    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public Integer getSex() {
        return sex;
    }

    /**
     * Sets the user's gender.
     * The value is represented by an integer, and defined in ISO/IEC 18013-1 and ISO/IEC 18013-2.
     *
     * @param sex {@link Integer}
     */
    public void setSex(Integer sex) {
        this.sex = sex;
    }

    @Override
    public Date getBirthdate() {
        return birthdate;
    }

    /**
     * Sets the user's birthdate
     *
     * @param birthdate {@link Date}
     */
    public void setBirthdate(Date birthdate) {
        this.birthdate = birthdate;
    }

    @Override
    public String getPhoneNumber() {
        return phoneNumber;
    }

    /**
     * Sets the user's preferred telephone number
     *
     * @param phoneNumber {@link String}
     */
    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    @Override
    public String getPostalAddress() {
        return postalAddress;
    }

    /**
     * Sets the place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.).
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @param postalAddress {@link String}
     */
    public void setPostalAddress(String postalAddress) {
        this.postalAddress = postalAddress;
    }

    @Override
    public String getAddressStreet() {
        return addressStreet;
    }

    /**
     * Sets the name of the street where the user to whom the person identification data relates currently resides.
     *
     * @param addressStreet {@link String}
     */
    public void setAddressStreet(String addressStreet) {
        this.addressStreet = addressStreet;
    }

    @Override
    public String getAddressHouseNumber() {
        return addressHouseNumber;
    }

    /**
     * Sets the house number where the user to whom the person identification data relates currently resides,
     * including any affix or suffix.
     *
     * @param addressHouseNumber {@link String}
     */
    public void setAddressHouseNumber(String addressHouseNumber) {
        this.addressHouseNumber = addressHouseNumber;
    }

    @Override
    public String getAddressCity() {
        return addressCity;
    }

    /**
     * Sets the city where the mDL holder lives.
     *
     * @param addressCity {@link String}
     */
    public void setAddressCity(String addressCity) {
        this.addressCity = addressCity;
    }

    @Override
    public String getAddressState() {
        return addressState;
    }

    /**
     * Sets the state/province/district where the mDL holder lives.
     *
     * @param addressState {@link String}
     */
    public void setAddressState(String addressState) {
        this.addressState = addressState;
    }

    @Override
    public String getAddressPostalCode() {
        return addressPostalCode;
    }

    /**
     * Sets the postal code of the mDL holder.
     *
     * @param addressPostalCode {@link String}
     */
    public void setAddressPostalCode(String addressPostalCode) {
        this.addressPostalCode = addressPostalCode;
    }

    @Override
    public String getAddressCountry() {
        return addressCountry;
    }

    /**
     * Sets the country where the mDL holder lives as a two letter country code (alpha-2 code)
     * defined in ISO 3166-1.
     *
     * @param addressCountry {@link String}
     */
    public void setAddressCountry(String addressCountry) {
        this.addressCountry = addressCountry;
    }

    @Override
    public String getPlaceOfBirthCountry() {
        return placeOfBirthCountry;
    }

    /**
     * Sets user's place of birth country
     *
     * @param placeOfBirthCountry {@link String}
     */
    public void setPlaceOfBirthCountry(String placeOfBirthCountry) {
        this.placeOfBirthCountry = placeOfBirthCountry;
    }

    @Override
    public String getPlaceOfBirthRegion() {
        return placeOfBirthRegion;
    }

    /**
     * Sets user's place of birth region
     *
     * @param placeOfBirthRegion {@link String}
     */
    public void setPlaceOfBirthRegion(String placeOfBirthRegion) {
        this.placeOfBirthRegion = placeOfBirthRegion;
    }

    @Override
    public String getPlaceOfBirthLocality() {
        return placeOfBirthLocality;
    }

    /**
     * Sets user's place of birth locality
     *
     * @param placeOfBirthLocality {@link String}
     */
    public void setPlaceOfBirthLocality(String placeOfBirthLocality) {
        this.placeOfBirthLocality = placeOfBirthLocality;
    }

    @Override
    public List<String> getNationalities() {
        return nationalities;
    }

    /**
     * Sets user's nationalities using ICAO 3-letter codes.
     * This type of nationality providing is used within EAA documents conformant to PID Rulebook.
     *
     * @param nationalities an array of of {@link String}s
     */
    public void setNationalities(String... nationalities) {
        if (Utils.isArrayNotEmpty(nationalities)) {
            this.nationalities = Arrays.asList(nationalities);
        } else {
            this.nationalities = null;
        }
    }

    /**
     * Sets user's nationalities using ICAO 3-letter codes.
     * This type of nationality providing is used within EAA documents conformant to PID Rulebook.
     *
     * @param nationalities a list of {@link String}s
     */
    public void setNationalities(List<String> nationalities) {
        this.nationalities = nationalities;
    }

    @Override
    public String getBirthGivenName() {
        return birthGivenName;
    }

    /**
     * Sets user's first or given name when they were born
     *
     * @param birthGivenName {@link String}
     */
    public void setBirthGivenName(String birthGivenName) {
        this.birthGivenName = birthGivenName;
    }

    @Override
    public String getBirthFamilyName() {
        return birthFamilyName;
    }

    /**
     * Sets user's family or last name when they were born
     *
     * @param birthFamilyName {@link String}
     */
    public void setBirthFamilyName(String birthFamilyName) {
        this.birthFamilyName = birthFamilyName;
    }

    @Override
    public String getTitle() {
        return title;
    }

    /**
     * Sets user's title, e.g., "Dr"
     *
     * @param title {@link String}
     */
    public void setTitle(String title) {
        this.title = title;
    }

    @Override
    public String getMobilePhoneNumber() {
        return mobilePhoneNumber;
    }

    /**
     * Sets user's mobile phone number
     *
     * @param mobilePhoneNumber {@link String}
     */
    public void setMobilePhoneNumber(String mobilePhoneNumber) {
        this.mobilePhoneNumber = mobilePhoneNumber;
    }

    @Override
    public String getPseudonym() {
        return pseudonym;
    }

    /**
     * Sets user's stage name, religious name or any other type of alias/pseudonym
     *
     * @param pseudonym {@link String}
     */
    public void setPseudonym(String pseudonym) {
        this.pseudonym = pseudonym;
    }

    @Override
    public String getIssuingCountry() {
        return issuingCountry;
    }

    /**
     * Sets alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory
     *
     * @param issuingCountry {@link String}
     */
    public void setIssuingCountry(String issuingCountry) {
        this.issuingCountry = issuingCountry;
    }

    @Override
    public String getIssuingAuthority() {
        return issuingAuthority;
    }

    /**
     * Sets issuing authority name.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @param issuingAuthority {@link String}
     */
    public void setIssuingAuthority(String issuingAuthority) {
        this.issuingAuthority = issuingAuthority;
    }

    @Override
    public String getDocumentNumber() {
        return documentNumber;
    }

    /**
     * Sets the number assigned or calculated by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @param documentNumber {@link String}
     */
    public void setDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
    }

    @Override
    public String getPersonalAdministrativeNumber() {
        return personalAdministrativeNumber;
    }

    /**
     * Sets an audit control number assigned by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @param personalAdministrativeNumber {@link String}
     */
    public void setPersonalAdministrativeNumber(String personalAdministrativeNumber) {
        this.personalAdministrativeNumber = personalAdministrativeNumber;
    }

    @Override
    public Integer getAgeInYears() {
        return ageInYears;
    }

    /**
     * Sets the date the age of the mDL holder
     *
     * @param ageInYears {@link Number}
     */
    public void setAgeInYears(Integer ageInYears) {
        this.ageInYears = ageInYears;
    }

    @Override
    public Integer getAgeBirthYear() {
        return ageBirthYear;
    }

    /**
     * Sets the year when the mDL holder was born
     *
     * @param ageBirthYear {@link Number}
     */
    public void setAgeBirthYear(Integer ageBirthYear) {
        this.ageBirthYear = ageBirthYear;
    }

    @Override
    public Map<Integer, Boolean> getAgeOverNN() {
        return ageOverNN;
    }

    /**
     * Sets a list of elements is used to convey to an mDL verifier, in a data-minimized fashion, if the mDL holder
     * is as old or older than a specified age, or if the mDL holder is younger than a specified age.
     *
     * @param age {@link Integer} representing an age
     * @param isOver {@link Boolean} defining whether the equal or over the defined age
     */
    public void setAgeOverNN(Integer age, Boolean isOver) {
        if (ageOverNN == null) {
            this.ageOverNN = new LinkedHashMap<>();
        }
        this.ageOverNN.put(age, isOver);
    }

    @Override
    public String getIssuingJurisdiction() {
        return issuingJurisdiction;
    }

    /**
     * Sets a country subdivision code of the jurisdiction that issued the mDL as defined in
     * ISO 3166-2:2020, Clause 8.
     *
     * @param issuingJurisdiction {@link String}
     */
    public void setIssuingJurisdiction(String issuingJurisdiction) {
        this.issuingJurisdiction = issuingJurisdiction;
    }

    @Override
    public String getTrustAnchor() {
        return trustAnchor;
    }

    /**
     * Sets the URL at which a machine-readable version of the trust anchor to be used for
     * verifying the PID can be found or looked up.
     *
     * @param trustAnchor {@link String}
     */
    public void setTrustAnchor(String trustAnchor) {
        this.trustAnchor = trustAnchor;
    }

    @Override
    public String getIssuingAuthorityRegistrationIdentifier() {
        return issuingAuthorityRegistrationIdentifier;
    }

    /**
     * Sets the registration identifier of the legal entity on whose behalf the EAA has been issued.
     *
     * @param issuingAuthorityRegistrationIdentifier {@link String}
     */
    public void setIssuingAuthorityRegistrationIdentifier(String issuingAuthorityRegistrationIdentifier) {
        this.issuingAuthorityRegistrationIdentifier = issuingAuthorityRegistrationIdentifier;
    }

    @Override
    public Date getAdministrativeIssuanceDate() {
        return administrativeIssuanceDate;
    }

    /**
     * Sets the date when the data (e.g. a PID) was issued
     *
     * @param administrativeIssuanceDate {@link Date}
     */
    public void setAdministrativeIssuanceDate(Date administrativeIssuanceDate) {
        this.administrativeIssuanceDate = administrativeIssuanceDate;
    }

    @Override
    public Date getAdministrativeExpirationDate() {
        return administrativeExpirationDate;
    }

    /**
     * Sets the date when the data (e.g. a PID) will expire
     *
     * @param administrativeExpirationDate {@link Date}
     */
    public void setAdministrativeExpirationDate(Date administrativeExpirationDate) {
        this.administrativeExpirationDate = administrativeExpirationDate;
    }

    /**
     * Adds a new claim.
     * A hash will be computed for the claim, if applicable.
     *
     * @param claim {@link AttestationClaim} to add
     */
    public void addClaim(C claim) {
        if (claim != null) {
            otherClaims.add(claim);
        }
    }

    @Override
    public List<C> getOtherClaims() {
        return otherClaims;
    }

    @Override
    public String toString() {
        return "AbstractEAAClaimParameters [" +
                "givenName='" + givenName + '\'' +
                ", familyName='" + familyName + '\'' +
                ", birthdate=" + birthdate +
                ", nationalities=" + nationalities +
                ", email='" + email + '\'' +
                ", phoneNumber='" + phoneNumber + '\'' +
                ", addressFull='" + postalAddress + '\'' +
                ", addressHouseNumber='" + addressHouseNumber + '\'' +
                ", addressStreet='" + addressStreet + '\'' +
                ", addressCity='" + addressCity + '\'' +
                ", addressState='" + addressState + '\'' +
                ", addressPostalCode='" + addressPostalCode + '\'' +
                ", addressCountry='" + addressCountry + '\'' +
                ", placeOfBirthCountry='" + placeOfBirthCountry + '\'' +
                ", placeOfBirthRegion='" + placeOfBirthRegion + '\'' +
                ", placeOfBirthLocality='" + placeOfBirthLocality + '\'' +
                ", birthGivenName='" + birthGivenName + '\'' +
                ", birthFamilyName='" + birthFamilyName + '\'' +
                ", title='" + title + '\'' +
                ", mobilePhoneNumber='" + mobilePhoneNumber + '\'' +
                ", pseudonym='" + pseudonym + '\'' +
                ", personalAdministrativeNumber='" + personalAdministrativeNumber + '\'' +
                ", sex=" + sex +
                ", issuingCountry='" + issuingCountry + '\'' +
                ", issuingAuthority='" + issuingAuthority + '\'' +
                ", issuingJurisdiction='" + issuingJurisdiction + '\'' +
                ", documentNumber='" + documentNumber + '\'' +
                ", ageInYears=" + ageInYears +
                ", ageBirthYear=" + ageBirthYear +
                ", trustAnchor='" + trustAnchor + '\'' +
                ", ageOverNN=" + ageOverNN +
                ", issuingAuthorityRegistrationIdentifier='" + issuingAuthorityRegistrationIdentifier + '\'' +
                ", administrativeIssuanceDate=" + administrativeIssuanceDate +
                ", administrativeExpirationDate=" + administrativeExpirationDate +
                ", otherClaims=" + otherClaims +
                ']';
    }

}
