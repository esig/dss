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
package eu.europa.esig.dss.attestation.sd.jwt.creation;

import eu.europa.esig.dss.attestation.common.creation.AbstractAttestationClaimParameters;
import eu.europa.esig.dss.utils.Utils;

import java.util.Date;
import java.util.List;

/**
 * Contains parameters for SD-JWT VC creation which may or may not be made selectively disclosable
 *
 */
public class SDJWTClaimParameters extends AbstractAttestationClaimParameters<SDJWTClaim> {

    // ietf-oauh-sd-jwt-vc

    /** EAA subject */
    private String subject;

    // OpenID Connect Core 1.0

    /** URL of the End-User's profile picture. */
    private String picture;

    /** Casual or informal name by which the End-User wishes to be referred to. */
    private String nickname;

    /** Preferred shorthand name or nickname of the End-User. */
    private String preferredNickname;

    /** Full name of the End-User in displayable form. */
    private String name;

    /** Middle name(s) of the End-User. */
    private String middleName;

    /** URL of the End-User's profile page. */
    private String profile;

    /** URL of the End-User's personal website or blog. */
    private String website;

    /** Indicates whether the End-User's email address has been verified. */
    private Boolean emailVerified;

    /** End-User's gender. */
    private String gender;

    /** End-User's time zone, represented as an IANA time zone identifier. */
    private String zoneinfo;

    /** End-User's locale, represented as a BCP47 language tag. */
    private String locale;

    /** Indicates whether the End-User's phone number has been verified. */
    private Boolean phoneNumberVerified;

    /** Time when the End-User's information was last updated. */
    private Date updatedAt;

    // OpenID Connect for Identity Assurance Claims Registration 1.0

    /** Middle name(s) assigned to the End-User at birth. */
    private String birthMiddleName;

    /** Salutation or honorific used when addressing the End-User (e.g. Mr., Ms., Dr.). */
    private String salutation;

    // PID Rulebook claims

    /** Expiration date of the identity document or credential. */
    private Date dateOfExpiry;

    /** Issuance date of the identity document or credential. */
    private Date dateOfIssuance;

    // ETSI TS 119 472-1 claims

    /**
     * The subject attribute identifier
     */
    private String attestedAttributesSubjectIdentifier;

    /**
     * The subject attribute pseudonym
     */
    private String attestedAttributesSubjectPseudonym;

    /**
     * The list of attributes associated with the attribute subject
     */
    private List<String> attestedAttributes;

    /**
     * Default constructor
     */
    public SDJWTClaimParameters() {
        // empty
    }

    /**
     * Gets the EAA subject
     *
     * @return {@link String}
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Sets the EAA subject
     *
     * @param subject {@link String}
     */
    public void setSubject(final String subject) {
        this.subject = subject;
    }

    /**
     * Gets a "picture" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link String} the picture
     */
    public String getPicture() {
        return picture;
    }

    /**
     * Sets a "picture" claim value as defined by OpenID Connect Core 1.0
     *
     * @param picture {@link String} the picture
     */
    public void setPicture(final String picture) {
        this.picture = picture;
    }

    /**
     * Gets a "nickname" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link String} the nickname
     */
    public String getNickname() {
        return nickname;
    }

    /**
     * Sets a "nickname" claim value as defined by OpenID Connect Core 1.0
     *
     * @param nickname {@link String} the nickname
     */
    public void setNickname(final String nickname) {
        this.nickname = nickname;
    }

    /**
     * Gets a "preferred_username" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link String} the preferred nickname
     */
    public String getPreferredNickname() {
        return preferredNickname;
    }

    /**
     * Sets a "preferred_username" claim value as defined by OpenID Connect Core 1.0
     *
     * @param preferredNickname {@link String} the preferred nickname
     */
    public void setPreferredNickname(final String preferredNickname) {
        this.preferredNickname = preferredNickname;
    }

    /**
     * Gets a "name" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link String} the full name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets a "name" claim value as defined by OpenID Connect Core 1.0
     *
     * @param name {@link String} the full name
     */
    public void setName(final String name) {
        this.name = name;
    }

    /**
     * Gets a "middle_name" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link String} value of the middle name
     */
    public String getMiddleName() {
        return middleName;
    }

    /**
     * Sets a "middle_name" claim value as defined by OpenID Connect Core 1.0
     *
     * @param middleName {@link String} value of the middle name
     */
    public void setMiddleName(final String middleName) {
        this.middleName = middleName;
    }

    /**
     * Gets a "profile" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link String} the profile URL
     */
    public String getProfile() {
        return profile;
    }

    /**
     * Sets a "profile" claim value as defined by OpenID Connect Core 1.0
     *
     * @param profile {@link String} the profile URL
     */
    public void setProfile(final String profile) {
        this.profile = profile;
    }

    /**
     * Gets a "website" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link String} the website URL
     */
    public String getWebsite() {
        return website;
    }

    /**
     * Sets a "website" claim value as defined by OpenID Connect Core 1.0
     *
     * @param website {@link String} the website URL
     */
    public void setWebsite(final String website) {
        this.website = website;
    }

    /**
     * Gets an "email_verified" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link Boolean} whether the email has been verified
     */
    public Boolean getEmailVerified() {
        return emailVerified;
    }

    /**
     * Sets an "email_verified" claim value as defined by OpenID Connect Core 1.0
     *
     * @param emailVerified {@link Boolean} whether the email has been verified
     */
    public void setEmailVerified(final Boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    /**
     * Gets a "gender" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link String} the gender
     */
    public String getGender() {
        return gender;
    }

    /**
     * Sets a "gender" claim value as defined by OpenID Connect Core 1.0
     *
     * @param gender {@link String} the gender
     */
    public void setGender(final String gender) {
        this.gender = gender;
    }

    /**
     * Gets a "zoneinfo" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link String} the time zone
     */
    public String getZoneinfo() {
        return zoneinfo;
    }

    /**
     * Sets a "zoneinfo" claim value as defined by OpenID Connect Core 1.0
     *
     * @param zoneinfo {@link String} the time zone
     */
    public void setZoneinfo(final String zoneinfo) {
        this.zoneinfo = zoneinfo;
    }

    /**
     * Gets a "locale" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link String} the locale
     */
    public String getLocale() {
        return locale;
    }

    /**
     * Sets a "locale" claim value as defined by OpenID Connect Core 1.0
     *
     * @param locale {@link String} the locale
     */
    public void setLocale(final String locale) {
        this.locale = locale;
    }

    /**
     * Gets a "phone_number_verified" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link Boolean} whether the phone number has been verified
     */
    public Boolean getPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    /**
     * Sets a "phone_number_verified" claim value as defined by OpenID Connect Core 1.0
     *
     * @param phoneNumberVerified {@link Boolean} whether the phone number has been verified
     */
    public void setPhoneNumberVerified(final Boolean phoneNumberVerified) {
        this.phoneNumberVerified = phoneNumberVerified;
    }

    /**
     * Gets an "updated_at" claim value as defined by OpenID Connect Core 1.0
     *
     * @return {@link Date} when user information was last updated
     */
    public Date getUpdatedAt() {
        return updatedAt;
    }

    /**
     * Sets an "updated_at" claim value as defined by OpenID Connect Core 1.0
     *
     * @param updatedAt {@link Date} when user information was last updated
     */
    public void setUpdatedAt(final Date updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * Gets a "birth_middle_name" claim value as defined by OpenID Connect for Identity Assurance Claims Registration 1.0
     *
     * @return {@link String} value of the birth middle name
     */
    public String getBirthMiddleName() {
        return birthMiddleName;
    }

    /**
     * Sets a "birth_middle_name" claim value as defined by OpenID Connect for Identity Assurance Claims Registration 1.0
     *
     * @param birthMiddleName {@link String} value of the birth middle name
     */
    public void setBirthMiddleName(final String birthMiddleName) {
        this.birthMiddleName = birthMiddleName;
    }

    /**
     * Gets a "salutation" claim value as defined by OpenID Connect for Identity Assurance Claims Registration 1.0
     *
     * @return {@link String} the end-user's salutation
     */
    public String getSalutation() {
        return salutation;
    }

    /**
     * Sets a "salutation" claim value as defined by OpenID Connect for Identity Assurance Claims Registration 1.0
     *
     * @param salutation {@link String} the end-user's salutation
     */
    public void setSalutation(final String salutation) {
        this.salutation = salutation;
    }

    /**
     * Gets a "date_of_expiry" claim value as defined by the PID Rulebook
     *
     * @return {@link Date} the date of expiry
     */
    public Date getDateOfExpiry() {
        return dateOfExpiry;
    }

    /**
     * Sets a "date_of_expiry" claim value as defined by the PID Rulebook
     *
     * @param dateOfExpiry {@link Date} the date of expiry
     */
    public void setDateOfExpiry(final Date dateOfExpiry) {
        this.dateOfExpiry = dateOfExpiry;
    }

    /**
     * Gets a "date_of_issuance" claim value as defined by the PID Rulebook
     *
     * @return {@link Date} the date of issuance
     */
    public Date getDateOfIssuance() {
        return dateOfIssuance;
    }

    /**
     * Sets a "date_of_issuance" claim value as defined by the PID Rulebook
     *
     * @param dateOfIssuance {@link Date} the date of issuance
     */
    public void setDateOfIssuance(final Date dateOfIssuance) {
        this.dateOfIssuance = dateOfIssuance;
    }

    /**
     * Gets the subject attribute identifier
     *
     * @return {@link String}
     */
    public String getAttestedAttributesSubjectIdentifier() {
        return attestedAttributesSubjectIdentifier;
    }

    /**
     * Sets the subject attribute identifier
     *
     * @param attestedAttributesSubjectIdentifier {@link String}
     * @param attestedAttributes a list of {@link String} attributes associated to the attribute subject
     */
    public void setAttestedAttributesSubjectIdentifier(String attestedAttributesSubjectIdentifier, List<String> attestedAttributes) {
        if (attestedAttributesSubjectIdentifier == null != Utils.isCollectionEmpty(attestedAttributes)) {
            throw new IllegalArgumentException("Attested attributes shall be present for an attested attributes subject identifier!");
        }
        this.attestedAttributesSubjectIdentifier = attestedAttributesSubjectIdentifier;
        this.attestedAttributes = attestedAttributes;
    }

    /**
     * Gets the pseudonym of the attribute subject
     *
     * @return {@link String}
     */
    public String getAttestedAttributesSubjectPseudonym() {
        return attestedAttributesSubjectPseudonym;
    }

    /**
     * Sets the claim for associating a set of attributes to one entity different than the EAA subject,
     * when pseudonym is used.
     *
     * @param pseudonym {@link String}  the subject attribute pseudonym
     * @param attestedAttributes a list of {@link String} attributes associated to the attribute subject
     */
    public void setAttestedAttributesSubjectPseudonym(String pseudonym, List<String> attestedAttributes) {
        if (pseudonym == null != Utils.isCollectionEmpty(attestedAttributes)) {
            throw new IllegalArgumentException("Attested attributes shall be present for an attested attributes subject pseudonym!");
        }
        this.attestedAttributesSubjectPseudonym = pseudonym;
        this.attestedAttributes = attestedAttributes;
    }

    /**
     * Gets a list of attributes associated to the attribute subject
     *
     * @return {@link String}
     */
    public List<String> getAttestedAttributes() {
        return attestedAttributes;
    }

    /**
     * Adds a custom claim with the given name and a value.
     * The claim will be added to the root level of the payload.
     *
     * @param name {@link String}
     * @param value {@link Object}
     */
    public void addClaim(final String name, final Object value) {
        addClaim(SDJWTClaim.create(name, value));
    }

    @Override
    public String toString() {
        return "SDJWTClaimParameters [" +
                "picture='" + picture + '\'' +
                ", nickname='" + nickname + '\'' +
                ", preferredNickname='" + preferredNickname + '\'' +
                ", name='" + name + '\'' +
                ", middleName='" + middleName + '\'' +
                ", profile='" + profile + '\'' +
                ", website='" + website + '\'' +
                ", emailVerified=" + emailVerified +
                ", gender='" + gender + '\'' +
                ", zoneinfo='" + zoneinfo + '\'' +
                ", locale='" + locale + '\'' +
                ", phoneNumberVerified=" + phoneNumberVerified +
                ", updatedAt=" + updatedAt +
                ", birthMiddleName='" + birthMiddleName + '\'' +
                ", salutation='" + salutation + '\'' +
                ", dateOfExpiry=" + dateOfExpiry +
                ", dateOfIssuance=" + dateOfIssuance +
                ", attestedAttributesSubjectIdentifier='" + attestedAttributes + '\'' +
                ", attestedAttributesSubjectPseudonym='" + attestedAttributesSubjectPseudonym + '\'' +
                "] " + super.toString();
    }

}
