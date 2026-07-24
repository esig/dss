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

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Contains parameters for individual claims to be included within EAA either as selectively disclosable
 * or non-selectively disclosable claims
 *
 * @param <C> implementation of {@link AttestationClaim} for the EAA format
 */
public interface AttestationClaimParameters<C extends AttestationClaim> {

    /**
     * Gets the issuance date of the digital credentials
     *
     * @return {@link Date}
     */
    Date getIssuanceDate();

    /**
     * Gets the user's first or given name information
     *
     * @return {@link String}
     */
    String getGivenName();

    /**
     * Gets the user's last name or surname information
     *
     * @return {@link String}
     */
    String getFamilyName();

    /**
     * Gets the user's preferred email address
     *
     * @return {@link String}
     */
    String getEmail();

    /**
     * Gets the user's gender
     *
     * @return {@link Integer}
     */
    Integer getSex();

    /**
     * Gets the user's birthdate
     *
     * @return {@link Date}
     */
    Date getBirthdate();

    /**
     * Gets the user's preferred telephone number
     *
     * @return {@link String}
     */
    String getPhoneNumber();

    /**
     * Gets the place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.).
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link String}
     */
    String getPostalAddress();

    /**
     * Gets the name of the street where the user to whom the person identification data relates currently resides.
     *
     * @return {@link String}
     */
    String getAddressStreet();

    /**
     * Gets the house number where the user to whom the person identification data relates currently resides,
     * including any affix or suffix.
     *
     * @return {@link String}
     */
    String getAddressHouseNumber();

    /**
     * Gets the city where the mDL holder lives.
     *
     * @return {@link String}
     */
    String getAddressCity();

    /**
     * Gets the state/province/district where the mDL holder lives.
     *
     * @return {@link String}
     */
    String getAddressState();

    /**
     * Gets the postal code of the mDL holder.
     *
     * @return {@link String}
     */
    String getAddressPostalCode();

    /**
     * Gets the country where the mDL holder lives as a two letter country code (alpha-2 code)
     * defined in ISO 3166-1.
     *
     * @return {@link String}
     */
    String getAddressCountry();

    /**
     * Gets user's place of birth country
     *
     * @return {@link String}
     */
    String getPlaceOfBirthCountry();

    /**
     * Gets user's place of birth region
     *
     * @return {@link String}
     */
    String getPlaceOfBirthRegion();

    /**
     * Gets user's place of birth locality
     *
     * @return {@link String}
     */
    String getPlaceOfBirthLocality();

    /**
     * Gets user's nationalities using ICAO 3-letter codes
     *
     * @return a list of {@link String}s
     */
    List<String> getNationalities();

    /**
     * Gets user's first or given name when they were born
     *
     * @return {@link String}
     */
    String getBirthGivenName();

    /**
     * Gets user's family or last name when they were born
     *
     * @return {@link String}
     */
    String getBirthFamilyName();

    /**
     * Gets user's title, e.g., "Dr"
     *
     * @return {@link String}
     */
    String getTitle();

    /**
     * Gets user's mobile phone number
     *
     * @return {@link String}
     */
    String getMobilePhoneNumber();

    /**
     * Gets user's stage name, religious name or any other type of alias/pseudonym
     *
     * @return {@link String}
     */
    String getPseudonym();

    /**
     * Gets alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory
     *
     * @return {@link String}
     */
    String getIssuingCountry();

    /**
     * Gets issuing authority name.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link String}
     */
    String getIssuingAuthority();

    /**
     * Gets the number assigned or calculated by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link String}
     */
    String getDocumentNumber();

    /**
     * An audit control number assigned by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link String}
     */
    String getPersonalAdministrativeNumber();

    /**
     * Gets the date the age of the mDL holder
     *
     * @return {@link Number}
     */
    Integer getAgeInYears();

    /**
     * Gets the year when the mDL holder was born
     *
     * @return {@link Number}
     */
    Integer getAgeBirthYear();

    /**
     * Gets a list of elements is used to convey to an mDL verifier, in a data-minimized fashion, if the mDL holder
     * is as old or older than a specified age, or if the mDL holder is younger than a specified age.
     *
     * @return a map between {@link Integer} age and {@link Boolean} values
     */
    Map<Integer, Boolean> getAgeOverNN();

    /**
     * Gets a country subdivision code of the jurisdiction that issued the mDL as defined in
     * ISO 3166-2:2020, Clause 8.
     *
     * @return {@link String}
     */
    String getIssuingJurisdiction();

    /**
     * Gets the URL at which a machine-readable version of the trust anchor to be used for
     * verifying the PID can be found or looked up.
     *
     * @return {@link String}
     */
    String getTrustAnchor();

    /**
     * Gets the registration identifier of the legal entity on whose behalf the EAA has been issued.
     *
     * @return {@link String}
     */
    String getIssuingAuthorityRegistrationIdentifier();

    /**
     * Gets the date when the data (e.g. a PID) was issued
     *
     * @return {@link Date}
     */
    Date getAdministrativeIssuanceDate();

    /**
     * Gets the date when the data (e.g. a PID) will expire
     *
     * @return {@link Date}
     */
    Date getAdministrativeExpirationDate();

    /**
     * Gets a list of other arbitrary provided claims
     *
     * @return a list of other claims
     */
    List<C> getOtherClaims();

}
