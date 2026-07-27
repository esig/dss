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
package eu.europa.esig.dss.model.attestation.claim;

/**
 * Represents a "4.8 Credential Subject" claim defined in W3C Verifiable Credentials Data Model v2.0.
 *
 */
public interface VerifiedClaimCredentialSubject extends VerifiedClaim {

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
    VerifiedClaimString getGender();

    /**
     * Gets the user's birthdate, when present
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getBirthdate();

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
     * @return {@link VerifiedClaimPlaceOfBirth}
     */
    VerifiedClaimPlaceOfBirth getPlaceOfBirth();

    /**
     * Gets user's nationalities using ICAO 3-letter codes, when present
     *
     * @return {@link VerifiedClaimArray}
     */
    VerifiedClaimArray getNationalities();

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

}
