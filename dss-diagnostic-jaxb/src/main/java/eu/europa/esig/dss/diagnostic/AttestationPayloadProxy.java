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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.claim.AddressClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.AgeEqualOrOverClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.AgeOverNNClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.AttestedAttributesSubjectClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.BiometricTemplateXXClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.BirthdateClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.CredentialSubjectClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.CredentialSubjectProxy;
import eu.europa.esig.dss.diagnostic.claim.DeviceKeyClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegesClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.IntegrityClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.PlaceOfBirthClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.StatusClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.ValidityInfoClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAddressClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAgeEqualOrOverClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAgeOverNNClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestedAttributesSubjectClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBiometricTemplateXXClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDeviceKeyClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDrivingPrivilegesClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationPayload;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIntegrityClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStatusClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlValidityInfoClaim;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * This class provides an interface for selectively disposable claims extraction
 * 
 */
public class AttestationPayloadProxy {
    
    /** Wrapped attestation Payload to get access to */
    private final XmlAttestationPayload xmlAttestationPayload;

    /**
     * Default constructor
     * 
     * @param xmlAttestationPayload {@link XmlAttestationPayload}
     */
    public AttestationPayloadProxy(final XmlAttestationPayload xmlAttestationPayload) {
        this.xmlAttestationPayload = xmlAttestationPayload;
    }
    
    /**
     * Gets attestation identifier provided in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getIdentifier() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getIdentifier());
        }
        return null;
    }

    /**
     * Gets attestation issuer as defined in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getIssuer() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getIssuer());
        }
        return null;
    }

    /**
     * Gets attestation subject as defined in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getSubject() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getSubject());
        }
        return null;
    }

    /**
     * Gets attestation audience as defined in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getAudience() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getAudience());
        }
        return null;
    }

    /**
     * Gets attestation issuance time as defined in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getIssuedAt() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getIssuedAt());
        }
        return null;
    }

    /**
     * Gets attestation not before time as defined in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getNotBefore() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getNotBefore());
        }
        return null;
    }

    /**
     * Gets attestation expiration time as defined in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getExpiration() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getExpiration());
        }
        return null;
    }

    /**
     * Gets attestation update time as defined in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getUpdatedAt() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getUpdatedAt());
        }
        return null;
    }

    /**
     * Gets category URN provided in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getCategory() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getCategory());
        }
        return null;
    }

    /**
     * Gets attestation metadata type (e.g. 'vct' claim) as defined in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getVerifiableCredentialsType() {
        if (xmlAttestationPayload != null && xmlAttestationPayload.getVerifiableCredentialsType() != null) {
            return getClaim(xmlAttestationPayload.getVerifiableCredentialsType());
        }
        return null;
    }

    /**
     * Gets the integrity material for the attestation metadata (when present)
     *
     * @return {@link ClaimWrapper}
     */
    public IntegrityClaimWrapper getVerifiableCredentialsTypeIntegrity() {
        if (xmlAttestationPayload != null && xmlAttestationPayload.getVerifiableCredentialsType() != null) {
            return getIntegrityClaim(xmlAttestationPayload.getVerifiableCredentialsType().getIntegrity());
        }
        return null;
    }

    /**
     * Gets attestation revocation as defined in the attestation payload
     *
     * @return {@link StatusClaimWrapper}
     */
    public StatusClaimWrapper getStatus() {
        if (xmlAttestationPayload != null) {
            return getStatusClaim(xmlAttestationPayload.getStatus());
        }
        return null;
    }

    /**
     * Gets attestation nonce when defined in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getNonce() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getNonce());
        }
        return null;
    }

    /**
     * Gets attestation device key when defined in the attestation payload
     *
     * @return {@link ClaimWrapper}
     */
    public DeviceKeyClaimWrapper getDeviceKey() {
        if (xmlAttestationPayload != null) {
            return getDeviceKeyClaim(xmlAttestationPayload.getDeviceKey());
        }
        return null;
    }

    /**
     * Gets a version of the MobileSecurityObject.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getVersion() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getVersion());
        }
        return null;
    }

    /**
     * Gets a docType as used in Documents.
     * NOTE: This a mandatory non-disclosable property in comparison with {@code #getDocumentType}.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getDocType() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getDocType());
        }
        return null;
    }

    /**
     * Gets the information related to the validity of the MSO and its signature.
     *
     * @return {@link ValidityInfoClaimWrapper}
     */
    public ValidityInfoClaimWrapper getValidityInfo() {
        if (xmlAttestationPayload != null) {
            return getValidityInfoClaim(xmlAttestationPayload.getValidityInfo());
        }
        return null;
    }

    /**
     * Gets holder's full name when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getFullName() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getFullName()), getCredentialSubject().getFullName());
        }
        return null;
    }

    /**
     * Gets holder's first name when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getGivenName() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getGivenName()), getCredentialSubject().getGivenName());
        }
        return null;
    }

    /**
     * Gets holder's last or family name when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getFamilyName() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getFamilyName()), getCredentialSubject().getFamilyName());
        }
        return null;
    }

    /**
     * Gets holder's middle name when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getMiddleName() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getMiddleName()), getCredentialSubject().getMiddleName());
        }
        return null;
    }

    /**
     * Gets holder's alternative name when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getNickname() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getNickname()), getCredentialSubject().getNickname());
        }
        return null;
    }

    /**
     * Gets holder's preferred or short name when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getShortName() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getShortName()), getCredentialSubject().getShortName());
        }
        return null;
    }

    /**
     * Gets holder's profile URL when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getProfileUrl() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getProfileUrl()), getCredentialSubject().getProfileUrl());
        }
        return null;
    }

    /**
     * Gets holder's picture URL when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPictureUrl() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getPictureUrl()), getCredentialSubject().getPictureUrl());
        }
        return null;
    }

    /**
     * Gets holder's website when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getWebsiteUrl() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getWebsiteUrl()), getCredentialSubject().getWebsiteUrl());
        }
        return null;
    }

    /**
     * Gets holder's email when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getEmail() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getEmail()), getCredentialSubject().getEmail());
        }
        return null;
    }

    /**
     * Gets whether the holder's website has been verified if defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getEmailVerified() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getEmailVerified()), getCredentialSubject().getEmailVerified());
        }
        return null;
    }

    /**
     * Gets holder's gender when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getGender() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getGender()), getCredentialSubject().getGender());
        }
        return null;
    }

    /**
     * Gets holder's birthdate when defined within attestation Payload claims
     *
     * @return {@link BirthdateClaimWrapper}
     */
    public BirthdateClaimWrapper getBirthdate() {
        if (xmlAttestationPayload != null) {
            return get(getBirthdateClaim(xmlAttestationPayload.getBirthdate()), getCredentialSubject().getBirthdate());
        }
        return null;
    }

    /**
     * Gets holder's timezone when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getTimezone() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getTimezone()), getCredentialSubject().getTimezone());
        }
        return null;
    }

    /**
     * Gets holder's locale when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getLocale() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getLocale()), getCredentialSubject().getLocale());
        }
        return null;
    }

    /**
     * Gets holder's full address, when defined within attestation Payload claims
     *
     * @return {@link AddressClaimWrapper}
     */
    public AddressClaimWrapper getAddress() {
        if (xmlAttestationPayload != null) {
            return get(getAddressClaim(xmlAttestationPayload.getAddress()), getCredentialSubject().getAddress());
        }
        return null;
    }

    /**
     * Gets holder's phone number when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPhoneNumber() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getPhoneNumber()), getCredentialSubject().getPhoneNumber());
        }
        return null;
    }

    /**
     * Gets whether the holder's phone number has been verified if defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPhoneNumberVerified() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getPhoneNumberVerified()), getCredentialSubject().getPhoneNumberVerified());
        }
        return null;
    }

    /**
     * Gets holder's place of birth when defined within attestation Payload claims
     *
     * @return {@link PlaceOfBirthClaimWrapper}
     */
    public PlaceOfBirthClaimWrapper getPlaceOfBirth() {
        if (xmlAttestationPayload != null) {
            return get(getPlaceOfBirthClaim(xmlAttestationPayload.getPlaceOfBirth()), getCredentialSubject().getPlaceOfBirth());
        }
        return null;
    }

    /**
     * Gets holder's nationalities list when defined within attestation Payload claims.
     * NOTE: The values are usually represented by 3-letter nationality codes.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getNationalities() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getNationalities()), getCredentialSubject().getNationalities());
        }
        return null;
    }

    /**
     * Gets holder's last or family name at birth when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getBirthFamilyName() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getBirthFamilyName()), getCredentialSubject().getBirthFamilyName());
        }
        return null;
    }

    /**
     * Gets holder's first name at birth when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getBirthGivenName() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getBirthGivenName()), getCredentialSubject().getBirthGivenName());
        }
        return null;
    }

    /**
     * Gets holder's middle name at birth when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getBirthMiddleName() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getBirthMiddleName()), getCredentialSubject().getBirthMiddleName());
        }
        return null;
    }

    /**
     * Gets the name(s) which holder was born.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getBirthFullName() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getBirthFullName());
        }
        return null;
    }

    /**
     * Gets holder's preferred salutation when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getSalutation() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getSalutation()), getCredentialSubject().getSalutation());
        }
        return null;
    }

    /**
     * Gets holder's title when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getTitle() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getTitle()), getCredentialSubject().getTitle());
        }
        return null;
    }

    /**
     * Gets holder's mobile phone number when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getMobilePhoneNumber() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getMobilePhoneNumber()), getCredentialSubject().getMobilePhoneNumber());
        }
        return null;
    }

    /**
     * Gets holder's scenic name or pseudonym, they are known as, when defined within attestation Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPseudonym() {
        if (xmlAttestationPayload != null) {
            return get(getClaim(xmlAttestationPayload.getPseudonym()), getCredentialSubject().getPseudonym());
        }
        return null;
    }

    /* mdoc claims */

    /**
     * Gets issuing authority name.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getDocumentIssuingAuthority() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getIssuingAuthority());
        }
        return null;
    }

    /**
     * Gets alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getDocumentIssuingAuthorityCountry() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getIssuingCountry());
        }
        return null;
    }

    /**
     * Gets a country subdivision code of the jurisdiction that issued the mDL as defined in
     * ISO 3166-2:2020, Clause 8. The first part of the code shall be the same as the value for issuing_country.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getDocumentIssuingAuthorityJurisdiction() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getIssuingJurisdiction());
        }
        return null;
    }

    /**
     * Gets the distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F.
     * If no applicable distinguishing sign is available in ISO/IEC 18013-1, an IA may
     * use an empty identifier or another identifier by which it is internationally recognized.
     * In this case the IA should ensure there is no collision with other IA’s.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getDocumentIssuingAuthorityUNDistinguishingSign() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getUNDistinguishingSign());
        }
        return null;
    }

    /**
     * An audit control number assigned by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPersonalAdministrativeNumber() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getPersonalAdministrativeNumber());
        }
        return null;
    }

    /**
     * Gets the number assigned or calculated by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getDocumentNumber() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getDocumentNumber());
        }
        return null;
    }

    /**
     * Gets a reproduction of the mDL holder’s portrait.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPortrait() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getPortrait());
        }
        return null;
    }

    /**
     * Gets the categories of vehicles/restrictions/conditions contain information describing the driving privileges
     * of the mDL holder.
     *
     * @return {@link DrivingPrivilegesClaimWrapper}
     */
    public DrivingPrivilegesClaimWrapper getDrivingPrivileges() {
        if (xmlAttestationPayload != null) {
            return getDrivingPrivilegesClaim(xmlAttestationPayload.getDrivingPrivileges());
        }
        return null;
    }

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getHeight() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getHeight());
        }
        return null;
    }

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getWeight() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getWeight());
        }
        return null;
    }

    /**
     * Gets the mDL holder’s eye colour. The value shall be one of the following: “black”, “blue”,
     * “brown”, “dichromatic”, “grey”, “green”, “hazel”, “maroon”, “pink”, “unknown”.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getEyeColour() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getEyeColour());
        }
        return null;
    }

    /**
     * Gets the mDL holder’s hair colour. The value shall be one of the following: “bald”, “black”,
     * “blond”, “brown”, “grey”, “red”, “auburn”, “sandy”, “white”, “unknown”.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getHairColour() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getHairColour());
        }
        return null;
    }

    /**
     * Gets the place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.).
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getResidentPostalAddress() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getResidentPostalAddress());
        }
        return null;
    }

    /**
     * Gets the date when portrait was taken.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPortraitCaptureDate() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getPortraitCaptureDate());
        }
        return null;
    }

    /**
     * Gets the date the age of the mDL holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getAgeInYears() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getAgeInYears());
        }
        return null;
    }

    /**
     * Gets the year when the mDL holder was born
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getAgeBirthYear() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getAgeBirthYear());
        }
        return null;
    }

    /**
     * Gets the map of claims attesting whether the User to whom the person identification data relates is
     * at least NN years old. N &lt;&gt; 18. Multiple instances of this attribute may be present, provided the value
     * of NN is different in each of them. If present, the requirements in clause 7.2.5 of ISO/IEC 18013-5
     * are applicable for these attributes.
     *
     * @return {@link ClaimWrapper}
     */
    public AgeEqualOrOverClaimWrapper getAgeEqualOrOver() {
        if (xmlAttestationPayload != null) {
            return getAgeEqualOrOverClaim(xmlAttestationPayload.getAgeEqualOrOver());
        }
        return null;
    }

    /**
     * Gets a list of elements is used to convey to an mDL verifier, in a data-minimized fashion, if the mDL holder
     * is as old or older than a specified age, or if the mDL holder is younger than a specified age. To achieve
     * this, the mDL contains age attestation identifiers. An age attestation identifier has the format age_over_NN
     * where NN is a value from 00 to 99. The value of an age attestation identifier can be TRUE or FALSE.
     *
     * @return a list of {@link AgeOverNNClaimWrapper}s
     */
    public List<AgeOverNNClaimWrapper> getAgeOverList() {
        if (xmlAttestationPayload != null) {
            List<XmlAgeOverNNClaim> ageOverNN = xmlAttestationPayload.getAgeOverNN();
            if (ageOverNN != null && !ageOverNN.isEmpty()) {
                return ageOverNN.stream().map(AgeOverNNClaimWrapper::new).collect(Collectors.toList());
            }
        }
        return null;
    }

    /**
     * Gets the city where the mDL holder lives. The value shall only use latin1 characters
     * and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getResidentAddressCity() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getResidentAddressCity());
        }
        return null;
    }

    /**
     * Gets the state/province/district where the mDL holder lives.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getResidentAddressState() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getResidentAddressState());
        }
        return null;
    }

    /**
     * Gets the postal code of the mDL holder. The value shall only use latin1 characters
     * and shall have a maximum length of 150 characters.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getResidentAddressPostalCode() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getResidentAddressPostalCode());
        }
        return null;
    }

    /**
     * Gets the country where the mDL holder lives as a two letter country code (alpha-2 code)
     * defined in ISO 3166-1.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getResidentAddressCountry() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getResidentAddressCountry());
        }
        return null;
    }

    /**
     * Gets a list of elements contains optional facial, fingerprint, iris, or other biometric information of the mDL
     * holder.
     * A biometric template identifier has the format biometric_template_xx
     * where xx shall be replaced with the corresponding “Abstract value name” found in ISO/IEC 19785
     * 3:2020, Table 7, according to the following convention: capitalized characters are replaced with their
     * lowercase equivalent and spaces or non-alphanumeric characters are replaced by underscores (_).
     *
     * @return a list of {@link BiometricTemplateXXClaimWrapper}s
     */
    public List<BiometricTemplateXXClaimWrapper> getBiometricTemplateList() {
        if (xmlAttestationPayload != null) {
            List<XmlBiometricTemplateXXClaim> biometricTemplateList = xmlAttestationPayload.getBiometricTemplate();
            if (biometricTemplateList != null && !biometricTemplateList.isEmpty()) {
                return biometricTemplateList.stream().map(BiometricTemplateXXClaimWrapper::new).collect(Collectors.toList());
            }
        }
        return null;
    }

    /**
     * Gets an image of the signature or usual mark of the mDL holder, see 7.2.7 ISO/IEC 18013-5.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getSignatureUsualMark() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getSignatureUsualMark());
        }
        return null;
    }

    /**
     * Gets a reproduction of the holder’s fingerprint data (TBC).
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getFingerprint() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getFingerprint());
        }
        return null;
    }

    /**
     * Gets a business name of the holder.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getBusinessName() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getBusinessName());
        }
        return null;
    }

    /**
     * Gets a name of legal person.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getOrganizationName() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getOrganizationName());
        }
        return null;
    }

    /**
     * Gets the profession of the holder.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getProfession() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getProfession());
        }
        return null;
    }

    /**
     * Gets the father of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipFather() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipFather());
        }
        return null;
    }

    /**
     * Gets the mother of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipMother() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipMother());
        }
        return null;
    }

    /**
     * Gets the parent of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipParent() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipParent());
        }
        return null;
    }

    /**
     * Gets the son of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipSon() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipSon());
        }
        return null;
    }

    /**
     * Gets the daughter of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipDaughter() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipDaughter());
        }
        return null;
    }

    /**
     * Gets the brother of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipBrother() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipBrother());
        }
        return null;
    }

    /**
     * Gets the sister of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipSister() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipSister());
        }
        return null;
    }

    /**
     * Gets the sibling of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipSibling() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipSibling());
        }
        return null;
    }

    /**
     * Gets the spouse of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipSpouse() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipSpouse());
        }
        return null;
    }

    /**
     * Gets the father-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipFatherInLaw() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipFatherInLaw());
        }
        return null;
    }

    /**
     * Gets the mother-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipMotherInLaw() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipMotherInLaw());
        }
        return null;
    }

    /**
     * Gets the parent-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipParentInLaw() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipParentInLaw());
        }
        return null;
    }

    /**
     * Gets the son-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipSonInLaw() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipSonInLaw());
        }
        return null;
    }

    /**
     * Gets the daughter-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipDaughterInLaw() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipDaughterInLaw());
        }
        return null;
    }

    /**
     * Gets the child-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipChildInLaw() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipChildInLaw());
        }
        return null;
    }

    /**
     * Gets the parental authority of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipParentalAuthority() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipParentalAuthority());
        }
        return null;
    }

    /**
     * Gets the legal representative of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipLegalRepresentative() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipLegalRepresentative());
        }
        return null;
    }

    /**
     * Gets the voluntary agent of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipAgent() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getRelationshipAgent());
        }
        return null;
    }

    /**
     * Gets the document type, claimed by the attestation.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getClaimedDocumentType() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getDocumentType());
        }
        return null;
    }

    /**
     * Gets the date when the data (e.g. a PID) was issued
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getAdministrativeIssuanceDate() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getAdministrativeIssuanceDate());
        }
        return null;
    }

    /**
     * Gets the date when the data (e.g. a PID) will expire
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getAdministrativeExpirationDate() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getAdministrativeExpirationDate());
        }
        return null;
    }

    /**
     * Gets the URL at which a machine-readable version of the trust anchor to be used for
     * verifying the PID can be found or looked up.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getTrustAnchor() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getTrustAnchor());
        }
        return null;
    }

    /**
     * Gets the name of the street where the user to whom the person identification data relates currently resides.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getResidentAddressStreet() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getResidentAddressStreet());
        }
        return null;
    }

    /**
     * Gets the house number where the user to whom the person identification data relates currently resides,
     * including any affix or suffix.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getResidentAddressHouseNumber() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getResidentAddressHouseNumber());
        }
        return null;
    }

    /* ETSI TS 119 472-1 "5 Implementation of attestation based on SD-JWT VC" header parameters */

    /**
     * Gets the registration identifier of the legal entity on whose behalf the attestation has been issued.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getIssuingAuthorityRegistrationIdentifier() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getIssuingAuthorityRegistrationIdentifier());
        }
        return null;
    }

    /**
     * Gets the signal indicating that the attestation shall be used only once, and that it shall not be retained for future use.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getOneTimeUse() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getOneTimeUse());
        }
        return null;
    }

    /**
     * Gets the attestation short-lived component indicating that the validity period of the attestation is so short that
     * it shall not be necessary to check its revocation status.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getShortLived() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getShortLived());
        }
        return null;
    }

    /**
     * Gets the array of evidence elements.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getEvidence() {
        if (xmlAttestationPayload != null) {
            return getClaim(xmlAttestationPayload.getEvidence());
        }
        return null;
    }

    /**
     * Gets the claim for associating a set of attributes to one entity different than the attestation subject.
     *
     * @return {@link ClaimWrapper}
     */
    public AttestedAttributesSubjectClaimWrapper getAttestedAttributesSubject() {
        if (xmlAttestationPayload != null) {
            return getAttestedAttributesSubjectClaim(xmlAttestationPayload.getAttestedAttributesSubject());
        }
        return null;
    }

    /**
     * Gets a list of credential subject claims
     *
     * @return a list of {@link CredentialSubjectClaimWrapper}s
     */
    public List<CredentialSubjectClaimWrapper> getCredentialSubjectClaims() {
        if (xmlAttestationPayload != null) {
            CredentialSubjectProxy credentialSubject = getCredentialSubject();
            return credentialSubject.getCredentialSubjects();
        }
        return Collections.emptyList();
    }

    /**
     * Gets a list of claims incorporated within the attestation Payload or provided as disclosures,
     * which are not (yet) directly supported by the implementation.
     *
     * @return a lust of {@link ClaimWrapper}s
     */
    public List<ClaimWrapper> getOtherClaims() {
        if (xmlAttestationPayload != null && xmlAttestationPayload.getOtherClaim() != null) {
            return xmlAttestationPayload.getOtherClaim().stream().map(ClaimWrapper::new).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    /**
     * Gets a list of all claims present within an attestation Payload
     *
     * @return a list of {@link ClaimWrapper}s
     */
    public List<ClaimWrapper> getAllAttestationPayloadClaims() {
        if (xmlAttestationPayload == null) {
            return Collections.emptyList();
        }

        final List<ClaimWrapper> claimList = new ArrayList<>();

        if (xmlAttestationPayload.getIdentifier() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getIdentifier()));
        }
        if (xmlAttestationPayload.getIssuer() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getIssuer()));
        }
        if (xmlAttestationPayload.getSubject() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getSubject()));
        }
        if (xmlAttestationPayload.getAudience() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getAudience()));
        }
        if (xmlAttestationPayload.getIssuedAt() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getIssuedAt()));
        }
        if (xmlAttestationPayload.getNotBefore() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getNotBefore()));
        }
        if (xmlAttestationPayload.getExpiration() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getExpiration()));
        }
        if (xmlAttestationPayload.getUpdatedAt() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getUpdatedAt()));
        }
        if (xmlAttestationPayload.getCategory() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getCategory()));
        }
        if (xmlAttestationPayload.getVerifiableCredentialsType() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getVerifiableCredentialsType()));
            if (xmlAttestationPayload.getVerifiableCredentialsType().getIntegrity() != null) {
                claimList.add(getIntegrityClaim(xmlAttestationPayload.getVerifiableCredentialsType().getIntegrity()));
            }
        }
        if (xmlAttestationPayload.getStatus() != null) {
            claimList.add(getStatusClaim(xmlAttestationPayload.getStatus()));
        }
        if (xmlAttestationPayload.getNonce() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getNonce()));
        }
        if (xmlAttestationPayload.getDeviceKey() != null) {
            claimList.add(getDeviceKeyClaim(xmlAttestationPayload.getDeviceKey()));
        }
        if (xmlAttestationPayload.getVersion() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getVersion()));
        }
        if (xmlAttestationPayload.getDocType() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getDocType()));
        }
        if (xmlAttestationPayload.getValidityInfo() != null) {
            claimList.add(getValidityInfoClaim(xmlAttestationPayload.getValidityInfo()));
        }
        if (xmlAttestationPayload.getFullName() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getFullName()));
        }
        if (xmlAttestationPayload.getGivenName() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getGivenName()));
        }
        if (xmlAttestationPayload.getFamilyName() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getFamilyName()));
        }
        if (xmlAttestationPayload.getMiddleName() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getMiddleName()));
        }
        if (xmlAttestationPayload.getNickname() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getNickname()));
        }
        if (xmlAttestationPayload.getShortName() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getShortName()));
        }
        if (xmlAttestationPayload.getProfileUrl() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getProfileUrl()));
        }
        if (xmlAttestationPayload.getPictureUrl() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getPictureUrl()));
        }
        if (xmlAttestationPayload.getWebsiteUrl() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getWebsiteUrl()));
        }
        if (xmlAttestationPayload.getEmail() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getEmail()));
        }
        if (xmlAttestationPayload.getEmailVerified() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getEmailVerified()));
        }
        if (xmlAttestationPayload.getGender() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getGender()));
        }
        if (xmlAttestationPayload.getBirthdate() != null) {
            claimList.add(getBirthdateClaim(xmlAttestationPayload.getBirthdate()));
        }
        if (xmlAttestationPayload.getTimezone() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getTimezone()));
        }
        if (xmlAttestationPayload.getLocale() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getLocale()));
        }
        if (xmlAttestationPayload.getAddress() != null) {
            claimList.add(getAddressClaim(xmlAttestationPayload.getAddress()));
        }
        if (xmlAttestationPayload.getPhoneNumber() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getPhoneNumber()));
        }
        if (xmlAttestationPayload.getPhoneNumberVerified() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getPhoneNumberVerified()));
        }
        if (xmlAttestationPayload.getPlaceOfBirth() != null) {
            claimList.add(getPlaceOfBirthClaim(xmlAttestationPayload.getPlaceOfBirth()));
        }
        if (xmlAttestationPayload.getNationalities() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getNationalities()));
        }
        if (xmlAttestationPayload.getBirthFamilyName() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getBirthFamilyName()));
        }
        if (xmlAttestationPayload.getBirthGivenName() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getBirthGivenName()));
        }
        if (xmlAttestationPayload.getBirthMiddleName() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getBirthMiddleName()));
        }
        if (xmlAttestationPayload.getSalutation() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getSalutation()));
        }
        if (xmlAttestationPayload.getTitle() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getTitle()));
        }
        if (xmlAttestationPayload.getMobilePhoneNumber() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getMobilePhoneNumber()));
        }
        if (xmlAttestationPayload.getPseudonym() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getPseudonym()));
        }
        if (xmlAttestationPayload.getCredentialSubject() != null) {
            claimList.addAll(getCredentialSubject().getCredentialSubjects());
        }
        if (xmlAttestationPayload.getIssuingCountry() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getIssuingCountry()));
        }
        if (xmlAttestationPayload.getIssuingAuthority() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getIssuingAuthority()));
        }
        if (xmlAttestationPayload.getDocumentNumber() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getDocumentNumber()));
        }
        if (xmlAttestationPayload.getPortrait() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getPortrait()));
        }
        if (xmlAttestationPayload.getDrivingPrivileges() != null) {
            claimList.add(getDrivingPrivilegesClaim(xmlAttestationPayload.getDrivingPrivileges()));
        }
        if (xmlAttestationPayload.getUNDistinguishingSign() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getUNDistinguishingSign()));
        }
        if (xmlAttestationPayload.getPersonalAdministrativeNumber() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getPersonalAdministrativeNumber()));
        }
        if (xmlAttestationPayload.getHeight() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getHeight()));
        }
        if (xmlAttestationPayload.getWeight() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getWeight()));
        }
        if (xmlAttestationPayload.getEyeColour() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getEyeColour()));
        }
        if (xmlAttestationPayload.getHairColour() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getHairColour()));
        }
        if (xmlAttestationPayload.getResidentPostalAddress() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getResidentPostalAddress()));
        }
        if (xmlAttestationPayload.getPortraitCaptureDate() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getPortraitCaptureDate()));
        }
        if (xmlAttestationPayload.getAgeInYears() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getAgeInYears()));
        }
        if (xmlAttestationPayload.getAgeBirthYear() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getAgeBirthYear()));
        }
        if (xmlAttestationPayload.getAgeEqualOrOver() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getAgeEqualOrOver()));
        }
        if (xmlAttestationPayload.getAgeOverNN() != null) {
            for (XmlClaim item : xmlAttestationPayload.getAgeOverNN()) {
                claimList.add(getClaim(item));
            }
        }
        if (xmlAttestationPayload.getIssuingJurisdiction() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getIssuingJurisdiction()));
        }
        if (xmlAttestationPayload.getResidentAddressCity() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getResidentAddressCity()));
        }
        if (xmlAttestationPayload.getResidentAddressState() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getResidentAddressState()));
        }
        if (xmlAttestationPayload.getResidentAddressPostalCode() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getResidentAddressPostalCode()));
        }
        if (xmlAttestationPayload.getResidentAddressCountry() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getResidentAddressCountry()));
        }
        if (xmlAttestationPayload.getBiometricTemplate() != null) {
            for (XmlClaim item : xmlAttestationPayload.getBiometricTemplate()) {
                claimList.add(getClaim(item));
            }
        }
        if (xmlAttestationPayload.getSignatureUsualMark() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getSignatureUsualMark()));
        }
        if (xmlAttestationPayload.getFingerprint() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getFingerprint()));
        }
        if (xmlAttestationPayload.getBusinessName() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getBusinessName()));
        }
        if (xmlAttestationPayload.getOrganizationName() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getOrganizationName()));
        }
        if (xmlAttestationPayload.getBirthFullName() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getBirthFullName()));
        }
        if (xmlAttestationPayload.getProfession() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getProfession()));
        }
        if (xmlAttestationPayload.getRelationshipFather() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipFather()));
        }
        if (xmlAttestationPayload.getRelationshipMother() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipMother()));
        }
        if (xmlAttestationPayload.getRelationshipParent() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipParent()));
        }
        if (xmlAttestationPayload.getRelationshipSon() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipSon()));
        }
        if (xmlAttestationPayload.getRelationshipDaughter() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipDaughter()));
        }
        if (xmlAttestationPayload.getRelationshipBrother() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipBrother()));
        }
        if (xmlAttestationPayload.getRelationshipSister() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipSister()));
        }
        if (xmlAttestationPayload.getRelationshipSibling() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipSibling()));
        }
        if (xmlAttestationPayload.getRelationshipSpouse() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipSpouse()));
        }
        if (xmlAttestationPayload.getRelationshipFatherInLaw() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipFatherInLaw()));
        }
        if (xmlAttestationPayload.getRelationshipMotherInLaw() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipMotherInLaw()));
        }
        if (xmlAttestationPayload.getRelationshipParentInLaw() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipParentInLaw()));
        }
        if (xmlAttestationPayload.getRelationshipSonInLaw() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipSonInLaw()));
        }
        if (xmlAttestationPayload.getRelationshipDaughterInLaw() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipDaughterInLaw()));
        }
        if (xmlAttestationPayload.getRelationshipChildInLaw() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipChildInLaw()));
        }
        if (xmlAttestationPayload.getRelationshipParentalAuthority() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipParentalAuthority()));
        }
        if (xmlAttestationPayload.getRelationshipLegalRepresentative() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipLegalRepresentative()));
        }
        if (xmlAttestationPayload.getRelationshipAgent() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getRelationshipAgent()));
        }
        if (xmlAttestationPayload.getDocumentType() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getDocumentType()));
        }
        if (xmlAttestationPayload.getAdministrativeIssuanceDate() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getAdministrativeIssuanceDate()));
        }
        if (xmlAttestationPayload.getAdministrativeExpirationDate() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getAdministrativeExpirationDate()));
        }
        if (xmlAttestationPayload.getTrustAnchor() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getTrustAnchor()));
        }
        if (xmlAttestationPayload.getResidentAddressStreet() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getResidentAddressStreet()));
        }
        if (xmlAttestationPayload.getResidentAddressHouseNumber() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getResidentAddressHouseNumber()));
        }
        if (xmlAttestationPayload.getIssuingAuthorityRegistrationIdentifier() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getIssuingAuthorityRegistrationIdentifier()));
        }
        if (xmlAttestationPayload.getOneTimeUse() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getOneTimeUse()));
        }
        if (xmlAttestationPayload.getShortLived() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getShortLived()));
        }
        if (xmlAttestationPayload.getEvidence() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getEvidence()));
        }
        if (xmlAttestationPayload.getAttestedAttributesSubject() != null) {
            claimList.add(getClaim(xmlAttestationPayload.getAttestedAttributesSubject()));
        }
        if (xmlAttestationPayload.getOtherClaim() != null && !xmlAttestationPayload.getOtherClaim().isEmpty()) {
            List<ClaimWrapper> claimWrappers = xmlAttestationPayload.getOtherClaim().stream()
                    .map(this::getClaim).collect(Collectors.toList());
            claimList.addAll(claimWrappers);
        }

        return claimList;
    }

    private ClaimWrapper getClaim(XmlClaim xmlDisclosableClaim) {
        if (xmlDisclosableClaim == null) {
            return null;
        }
        return new ClaimWrapper(xmlDisclosableClaim);
    }
    
    private <T extends ClaimWrapper> T get(T... claims) {
        for (T claim : claims) {
            if (claim != null) {
                return claim;
            }
        }
        return null;
    }

    private DeviceKeyClaimWrapper getDeviceKeyClaim(XmlDeviceKeyClaim xmlDeviceKeyClaim) {
        if (xmlDeviceKeyClaim == null) {
            return null;
        }
        return new DeviceKeyClaimWrapper(xmlDeviceKeyClaim);
    }

    private ValidityInfoClaimWrapper getValidityInfoClaim(XmlValidityInfoClaim xmlValidityInfoClaim) {
        if (xmlValidityInfoClaim == null) {
            return null;
        }
        return new ValidityInfoClaimWrapper(xmlValidityInfoClaim);
    }

    private IntegrityClaimWrapper getIntegrityClaim(XmlIntegrityClaim xmlIntegrityClaim) {
        if (xmlIntegrityClaim == null) {
            return null;
        }
        return new IntegrityClaimWrapper(xmlIntegrityClaim);
    }

    private AddressClaimWrapper getAddressClaim(XmlAddressClaim xmlAddressClaim) {
        if (xmlAddressClaim == null) {
            return null;
        }
        return new AddressClaimWrapper(xmlAddressClaim);
    }

    private BirthdateClaimWrapper getBirthdateClaim(XmlClaim xmlBirthdateClaim) {
        if (xmlBirthdateClaim == null) {
            return null;
        }
        return new BirthdateClaimWrapper(xmlBirthdateClaim);
    }

    private PlaceOfBirthClaimWrapper getPlaceOfBirthClaim(XmlClaim xmlPlaceOfBirthClaim) {
        if (xmlPlaceOfBirthClaim == null) {
            return null;
        }
        return new PlaceOfBirthClaimWrapper(xmlPlaceOfBirthClaim);
    }

    private StatusClaimWrapper getStatusClaim(XmlStatusClaim xmlStatusClaim) {
        if (xmlStatusClaim == null) {
            return null;
        }
        return new StatusClaimWrapper(xmlStatusClaim);
    }
    
    private CredentialSubjectProxy getCredentialSubject() {
        return new CredentialSubjectProxy(xmlAttestationPayload.getCredentialSubject());
    }

    private DrivingPrivilegesClaimWrapper getDrivingPrivilegesClaim(XmlDrivingPrivilegesClaim xmlDrivingPrivilegesClaim) {
        if (xmlDrivingPrivilegesClaim == null) {
            return null;
        }
        return new DrivingPrivilegesClaimWrapper(xmlDrivingPrivilegesClaim);
    }

    private AttestedAttributesSubjectClaimWrapper getAttestedAttributesSubjectClaim(XmlAttestedAttributesSubjectClaim xmlAttestedAttributesSubjectClaim) {
        if (xmlAttestedAttributesSubjectClaim == null) {
            return null;
        }
        return new AttestedAttributesSubjectClaimWrapper(xmlAttestedAttributesSubjectClaim);
    }

    private AgeEqualOrOverClaimWrapper getAgeEqualOrOverClaim(XmlAgeEqualOrOverClaim xmlAgeEqualOrOverClaim) {
        if (xmlAgeEqualOrOverClaim == null) {
            return null;
        }
        return new AgeEqualOrOverClaimWrapper(xmlAgeEqualOrOverClaim);
    }
    
}
