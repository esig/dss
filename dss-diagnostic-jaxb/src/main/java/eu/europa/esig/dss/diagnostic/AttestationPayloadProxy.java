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
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAAPayload;
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
    
    /** Wrapped EAA Payload to get access to */
    private final XmlEAAPayload xmlEAAPayload;

    /**
     * Default constructor
     * 
     * @param xmlEAAPayload {@link XmlEAAPayload}
     */
    public AttestationPayloadProxy(final XmlEAAPayload xmlEAAPayload) {
        this.xmlEAAPayload = xmlEAAPayload;
    }
    
    /**
     * Gets EAA identifier provided in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getIdentifier() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getIdentifier());
        }
        return null;
    }

    /**
     * Gets EAA issuer as defined in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getIssuer() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getIssuer());
        }
        return null;
    }

    /**
     * Gets EAA subject as defined in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getSubject() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getSubject());
        }
        return null;
    }

    /**
     * Gets EAA audience as defined in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getAudience() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getAudience());
        }
        return null;
    }

    /**
     * Gets EAA issuance time as defined in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getIssuedAt() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getIssuedAt());
        }
        return null;
    }

    /**
     * Gets EAA not before time as defined in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getNotBefore() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getNotBefore());
        }
        return null;
    }

    /**
     * Gets EAA expiration time as defined in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getExpiration() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getExpiration());
        }
        return null;
    }

    /**
     * Gets EAA update time as defined in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getUpdatedAt() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getUpdatedAt());
        }
        return null;
    }

    /**
     * Gets category URN provided in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getCategory() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getCategory());
        }
        return null;
    }

    /**
     * Gets EAA metadata type (e.g. 'vct' claim) as defined in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getVerifiableCredentialsType() {
        if (xmlEAAPayload != null && xmlEAAPayload.getVerifiableCredentialsType() != null) {
            return getClaim(xmlEAAPayload.getVerifiableCredentialsType());
        }
        return null;
    }

    /**
     * Gets the integrity material for the EAA metadata (when present)
     *
     * @return {@link ClaimWrapper}
     */
    public IntegrityClaimWrapper getVerifiableCredentialsTypeIntegrity() {
        if (xmlEAAPayload != null && xmlEAAPayload.getVerifiableCredentialsType() != null) {
            return getIntegrityClaim(xmlEAAPayload.getVerifiableCredentialsType().getIntegrity());
        }
        return null;
    }

    /**
     * Gets EAA revocation as defined in the EAA payload
     *
     * @return {@link StatusClaimWrapper}
     */
    public StatusClaimWrapper getStatus() {
        if (xmlEAAPayload != null) {
            return getStatusClaim(xmlEAAPayload.getStatus());
        }
        return null;
    }

    /**
     * Gets EAA nonce when defined in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getNonce() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getNonce());
        }
        return null;
    }

    /**
     * Gets EAA device key when defined in the EAA payload
     *
     * @return {@link ClaimWrapper}
     */
    public DeviceKeyClaimWrapper getDeviceKey() {
        if (xmlEAAPayload != null) {
            return getDeviceKeyClaim(xmlEAAPayload.getDeviceKey());
        }
        return null;
    }

    /**
     * Gets a version of the MobileSecurityObject.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getVersion() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getVersion());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getDocType());
        }
        return null;
    }

    /**
     * Gets the information related to the validity of the MSO and its signature.
     *
     * @return {@link ValidityInfoClaimWrapper}
     */
    public ValidityInfoClaimWrapper getValidityInfo() {
        if (xmlEAAPayload != null) {
            return getValidityInfoClaim(xmlEAAPayload.getValidityInfo());
        }
        return null;
    }

    /**
     * Gets holder's full name when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getFullName() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getFullName()), getCredentialSubject().getFullName());
        }
        return null;
    }

    /**
     * Gets holder's first name when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getGivenName() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getGivenName()), getCredentialSubject().getGivenName());
        }
        return null;
    }

    /**
     * Gets holder's last or family name when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getFamilyName() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getFamilyName()), getCredentialSubject().getFamilyName());
        }
        return null;
    }

    /**
     * Gets holder's middle name when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getMiddleName() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getMiddleName()), getCredentialSubject().getMiddleName());
        }
        return null;
    }

    /**
     * Gets holder's alternative name when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getNickname() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getNickname()), getCredentialSubject().getNickname());
        }
        return null;
    }

    /**
     * Gets holder's preferred or short name when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getShortName() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getShortName()), getCredentialSubject().getShortName());
        }
        return null;
    }

    /**
     * Gets holder's profile URL when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getProfileUrl() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getProfileUrl()), getCredentialSubject().getProfileUrl());
        }
        return null;
    }

    /**
     * Gets holder's picture URL when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPictureUrl() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getPictureUrl()), getCredentialSubject().getPictureUrl());
        }
        return null;
    }

    /**
     * Gets holder's website when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getWebsiteUrl() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getWebsiteUrl()), getCredentialSubject().getWebsiteUrl());
        }
        return null;
    }

    /**
     * Gets holder's email when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getEmail() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getEmail()), getCredentialSubject().getEmail());
        }
        return null;
    }

    /**
     * Gets whether the holder's website has been verified if defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getEmailVerified() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getEmailVerified()), getCredentialSubject().getEmailVerified());
        }
        return null;
    }

    /**
     * Gets holder's gender when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getGender() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getGender()), getCredentialSubject().getGender());
        }
        return null;
    }

    /**
     * Gets holder's birthdate when defined within EAA Payload claims
     *
     * @return {@link BirthdateClaimWrapper}
     */
    public BirthdateClaimWrapper getBirthdate() {
        if (xmlEAAPayload != null) {
            return get(getBirthdateClaim(xmlEAAPayload.getBirthdate()), getCredentialSubject().getBirthdate());
        }
        return null;
    }

    /**
     * Gets holder's timezone when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getTimezone() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getTimezone()), getCredentialSubject().getTimezone());
        }
        return null;
    }

    /**
     * Gets holder's locale when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getLocale() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getLocale()), getCredentialSubject().getLocale());
        }
        return null;
    }

    /**
     * Gets holder's full address, when defined within EAA Payload claims
     *
     * @return {@link AddressClaimWrapper}
     */
    public AddressClaimWrapper getAddress() {
        if (xmlEAAPayload != null) {
            return get(getAddressClaim(xmlEAAPayload.getAddress()), getCredentialSubject().getAddress());
        }
        return null;
    }

    /**
     * Gets holder's phone number when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPhoneNumber() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getPhoneNumber()), getCredentialSubject().getPhoneNumber());
        }
        return null;
    }

    /**
     * Gets whether the holder's phone number has been verified if defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPhoneNumberVerified() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getPhoneNumberVerified()), getCredentialSubject().getPhoneNumberVerified());
        }
        return null;
    }

    /**
     * Gets holder's place of birth when defined within EAA Payload claims
     *
     * @return {@link PlaceOfBirthClaimWrapper}
     */
    public PlaceOfBirthClaimWrapper getPlaceOfBirth() {
        if (xmlEAAPayload != null) {
            return get(getPlaceOfBirthClaim(xmlEAAPayload.getPlaceOfBirth()), getCredentialSubject().getPlaceOfBirth());
        }
        return null;
    }

    /**
     * Gets holder's nationalities list when defined within EAA Payload claims.
     * NOTE: The values are usually represented by 3-letter nationality codes.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getNationalities() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getNationalities()), getCredentialSubject().getNationalities());
        }
        return null;
    }

    /**
     * Gets holder's last or family name at birth when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getBirthFamilyName() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getBirthFamilyName()), getCredentialSubject().getBirthFamilyName());
        }
        return null;
    }

    /**
     * Gets holder's first name at birth when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getBirthGivenName() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getBirthGivenName()), getCredentialSubject().getBirthGivenName());
        }
        return null;
    }

    /**
     * Gets holder's middle name at birth when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getBirthMiddleName() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getBirthMiddleName()), getCredentialSubject().getBirthMiddleName());
        }
        return null;
    }

    /**
     * Gets the name(s) which holder was born.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getBirthFullName() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getBirthFullName());
        }
        return null;
    }

    /**
     * Gets holder's preferred salutation when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getSalutation() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getSalutation()), getCredentialSubject().getSalutation());
        }
        return null;
    }

    /**
     * Gets holder's title when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getTitle() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getTitle()), getCredentialSubject().getTitle());
        }
        return null;
    }

    /**
     * Gets holder's mobile phone number when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getMobilePhoneNumber() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getMobilePhoneNumber()), getCredentialSubject().getMobilePhoneNumber());
        }
        return null;
    }

    /**
     * Gets holder's scenic name or pseudonym, they are known as, when defined within EAA Payload claims
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPseudonym() {
        if (xmlEAAPayload != null) {
            return get(getClaim(xmlEAAPayload.getPseudonym()), getCredentialSubject().getPseudonym());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getIssuingAuthority());
        }
        return null;
    }

    /**
     * Gets alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getDocumentIssuingAuthorityCountry() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getIssuingCountry());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getIssuingJurisdiction());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getUNDistinguishingSign());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getPersonalAdministrativeNumber());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getDocumentNumber());
        }
        return null;
    }

    /**
     * Gets a reproduction of the mDL holder’s portrait.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPortrait() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getPortrait());
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
        if (xmlEAAPayload != null) {
            return getDrivingPrivilegesClaim(xmlEAAPayload.getDrivingPrivileges());
        }
        return null;
    }

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getHeight() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getHeight());
        }
        return null;
    }

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getWeight() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getWeight());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getEyeColour());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getHairColour());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getResidentPostalAddress());
        }
        return null;
    }

    /**
     * Gets the date when portrait was taken.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getPortraitCaptureDate() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getPortraitCaptureDate());
        }
        return null;
    }

    /**
     * Gets the date the age of the mDL holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getAgeInYears() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getAgeInYears());
        }
        return null;
    }

    /**
     * Gets the year when the mDL holder was born
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getAgeBirthYear() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getAgeBirthYear());
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
        if (xmlEAAPayload != null) {
            return getAgeEqualOrOverClaim(xmlEAAPayload.getAgeEqualOrOver());
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
        if (xmlEAAPayload != null) {
            List<XmlAgeOverNNClaim> ageOverNN = xmlEAAPayload.getAgeOverNN();
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getResidentAddressCity());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getResidentAddressState());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getResidentAddressPostalCode());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getResidentAddressCountry());
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
        if (xmlEAAPayload != null) {
            List<XmlBiometricTemplateXXClaim> biometricTemplateList = xmlEAAPayload.getBiometricTemplate();
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getSignatureUsualMark());
        }
        return null;
    }

    /**
     * Gets a reproduction of the holder’s fingerprint data (TBC).
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getFingerprint() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getFingerprint());
        }
        return null;
    }

    /**
     * Gets a business name of the holder.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getBusinessName() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getBusinessName());
        }
        return null;
    }

    /**
     * Gets a name of legal person.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getOrganizationName() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getOrganizationName());
        }
        return null;
    }

    /**
     * Gets the profession of the holder.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getProfession() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getProfession());
        }
        return null;
    }

    /**
     * Gets the father of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipFather() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipFather());
        }
        return null;
    }

    /**
     * Gets the mother of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipMother() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipMother());
        }
        return null;
    }

    /**
     * Gets the parent of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipParent() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipParent());
        }
        return null;
    }

    /**
     * Gets the son of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipSon() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipSon());
        }
        return null;
    }

    /**
     * Gets the daughter of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipDaughter() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipDaughter());
        }
        return null;
    }

    /**
     * Gets the brother of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipBrother() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipBrother());
        }
        return null;
    }

    /**
     * Gets the sister of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipSister() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipSister());
        }
        return null;
    }

    /**
     * Gets the sibling of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipSibling() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipSibling());
        }
        return null;
    }

    /**
     * Gets the spouse of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipSpouse() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipSpouse());
        }
        return null;
    }

    /**
     * Gets the father-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipFatherInLaw() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipFatherInLaw());
        }
        return null;
    }

    /**
     * Gets the mother-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipMotherInLaw() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipMotherInLaw());
        }
        return null;
    }

    /**
     * Gets the parent-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipParentInLaw() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipParentInLaw());
        }
        return null;
    }

    /**
     * Gets the son-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipSonInLaw() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipSonInLaw());
        }
        return null;
    }

    /**
     * Gets the daughter-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipDaughterInLaw() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipDaughterInLaw());
        }
        return null;
    }

    /**
     * Gets the child-in-law of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipChildInLaw() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipChildInLaw());
        }
        return null;
    }

    /**
     * Gets the parental authority of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipParentalAuthority() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipParentalAuthority());
        }
        return null;
    }

    /**
     * Gets the legal representative of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipLegalRepresentative() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipLegalRepresentative());
        }
        return null;
    }

    /**
     * Gets the voluntary agent of the holder
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getRelationshipAgent() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getRelationshipAgent());
        }
        return null;
    }

    /**
     * Gets the document type, claimed by the attestation.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getClaimedDocumentType() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getDocumentType());
        }
        return null;
    }

    /**
     * Gets the date when the data (e.g. a PID) was issued
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getAdministrativeIssuanceDate() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getAdministrativeIssuanceDate());
        }
        return null;
    }

    /**
     * Gets the date when the data (e.g. a PID) will expire
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getAdministrativeExpirationDate() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getAdministrativeExpirationDate());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getTrustAnchor());
        }
        return null;
    }

    /**
     * Gets the name of the street where the user to whom the person identification data relates currently resides.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getResidentAddressStreet() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getResidentAddressStreet());
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
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getResidentAddressHouseNumber());
        }
        return null;
    }

    /* ETSI TS 119 472-1 "5 Implementation of EAA based on SD-JWT VC" header parameters */

    /**
     * Gets the registration identifier of the legal entity on whose behalf the EAA has been issued.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getIssuingAuthorityRegistrationIdentifier() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getIssuingAuthorityRegistrationIdentifier());
        }
        return null;
    }

    /**
     * Gets the signal indicating that the EAA shall be used only once, and that it shall not be retained for future use.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getOneTimeUse() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getOneTimeUse());
        }
        return null;
    }

    /**
     * Gets the EAA short-lived component indicating that the validity period of the EAA is so short that
     * it shall not be necessary to check its revocation revocation.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getShortLived() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getShortLived());
        }
        return null;
    }

    /**
     * Gets the array of evidence elements.
     *
     * @return {@link ClaimWrapper}
     */
    public ClaimWrapper getEvidence() {
        if (xmlEAAPayload != null) {
            return getClaim(xmlEAAPayload.getEvidence());
        }
        return null;
    }

    /**
     * Gets the claim for associating a set of attributes to one entity different than the EAA subject.
     *
     * @return {@link ClaimWrapper}
     */
    public AttestedAttributesSubjectClaimWrapper getAttestedAttributesSubject() {
        if (xmlEAAPayload != null) {
            return getAttestedAttributesSubjectClaim(xmlEAAPayload.getAttestedAttributesSubject());
        }
        return null;
    }

    /**
     * Gets a list of credential subject claims
     *
     * @return a list of {@link CredentialSubjectClaimWrapper}s
     */
    public List<CredentialSubjectClaimWrapper> getCredentialSubjectClaims() {
        if (xmlEAAPayload != null) {
            CredentialSubjectProxy credentialSubject = getCredentialSubject();
            return credentialSubject.getCredentialSubjects();
        }
        return Collections.emptyList();
    }

    /**
     * Gets a list of claims incorporated within the EAA Payload or provided as disclosures,
     * which are not (yet) directly supported by the implementation.
     *
     * @return a lust of {@link ClaimWrapper}s
     */
    public List<ClaimWrapper> getOtherClaims() {
        if (xmlEAAPayload != null && xmlEAAPayload.getOtherClaim() != null) {
            return xmlEAAPayload.getOtherClaim().stream().map(ClaimWrapper::new).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    /**
     * Gets a list of all claims present within an EAA Payload
     *
     * @return a list of {@link ClaimWrapper}s
     */
    public List<ClaimWrapper> getAllEAAPayloadClaims() {
        if (xmlEAAPayload == null) {
            return Collections.emptyList();
        }

        final List<ClaimWrapper> claimList = new ArrayList<>();

        if (xmlEAAPayload.getIdentifier() != null) {
            claimList.add(getClaim(xmlEAAPayload.getIdentifier()));
        }
        if (xmlEAAPayload.getIssuer() != null) {
            claimList.add(getClaim(xmlEAAPayload.getIssuer()));
        }
        if (xmlEAAPayload.getSubject() != null) {
            claimList.add(getClaim(xmlEAAPayload.getSubject()));
        }
        if (xmlEAAPayload.getAudience() != null) {
            claimList.add(getClaim(xmlEAAPayload.getAudience()));
        }
        if (xmlEAAPayload.getIssuedAt() != null) {
            claimList.add(getClaim(xmlEAAPayload.getIssuedAt()));
        }
        if (xmlEAAPayload.getNotBefore() != null) {
            claimList.add(getClaim(xmlEAAPayload.getNotBefore()));
        }
        if (xmlEAAPayload.getExpiration() != null) {
            claimList.add(getClaim(xmlEAAPayload.getExpiration()));
        }
        if (xmlEAAPayload.getUpdatedAt() != null) {
            claimList.add(getClaim(xmlEAAPayload.getUpdatedAt()));
        }
        if (xmlEAAPayload.getCategory() != null) {
            claimList.add(getClaim(xmlEAAPayload.getCategory()));
        }
        if (xmlEAAPayload.getVerifiableCredentialsType() != null) {
            claimList.add(getClaim(xmlEAAPayload.getVerifiableCredentialsType()));
            if (xmlEAAPayload.getVerifiableCredentialsType().getIntegrity() != null) {
                claimList.add(getIntegrityClaim(xmlEAAPayload.getVerifiableCredentialsType().getIntegrity()));
            }
        }
        if (xmlEAAPayload.getStatus() != null) {
            claimList.add(getStatusClaim(xmlEAAPayload.getStatus()));
        }
        if (xmlEAAPayload.getNonce() != null) {
            claimList.add(getClaim(xmlEAAPayload.getNonce()));
        }
        if (xmlEAAPayload.getDeviceKey() != null) {
            claimList.add(getDeviceKeyClaim(xmlEAAPayload.getDeviceKey()));
        }
        if (xmlEAAPayload.getVersion() != null) {
            claimList.add(getClaim(xmlEAAPayload.getVersion()));
        }
        if (xmlEAAPayload.getDocType() != null) {
            claimList.add(getClaim(xmlEAAPayload.getDocType()));
        }
        if (xmlEAAPayload.getValidityInfo() != null) {
            claimList.add(getValidityInfoClaim(xmlEAAPayload.getValidityInfo()));
        }
        if (xmlEAAPayload.getFullName() != null) {
            claimList.add(getClaim(xmlEAAPayload.getFullName()));
        }
        if (xmlEAAPayload.getGivenName() != null) {
            claimList.add(getClaim(xmlEAAPayload.getGivenName()));
        }
        if (xmlEAAPayload.getFamilyName() != null) {
            claimList.add(getClaim(xmlEAAPayload.getFamilyName()));
        }
        if (xmlEAAPayload.getMiddleName() != null) {
            claimList.add(getClaim(xmlEAAPayload.getMiddleName()));
        }
        if (xmlEAAPayload.getNickname() != null) {
            claimList.add(getClaim(xmlEAAPayload.getNickname()));
        }
        if (xmlEAAPayload.getShortName() != null) {
            claimList.add(getClaim(xmlEAAPayload.getShortName()));
        }
        if (xmlEAAPayload.getProfileUrl() != null) {
            claimList.add(getClaim(xmlEAAPayload.getProfileUrl()));
        }
        if (xmlEAAPayload.getPictureUrl() != null) {
            claimList.add(getClaim(xmlEAAPayload.getPictureUrl()));
        }
        if (xmlEAAPayload.getWebsiteUrl() != null) {
            claimList.add(getClaim(xmlEAAPayload.getWebsiteUrl()));
        }
        if (xmlEAAPayload.getEmail() != null) {
            claimList.add(getClaim(xmlEAAPayload.getEmail()));
        }
        if (xmlEAAPayload.getEmailVerified() != null) {
            claimList.add(getClaim(xmlEAAPayload.getEmailVerified()));
        }
        if (xmlEAAPayload.getGender() != null) {
            claimList.add(getClaim(xmlEAAPayload.getGender()));
        }
        if (xmlEAAPayload.getBirthdate() != null) {
            claimList.add(getBirthdateClaim(xmlEAAPayload.getBirthdate()));
        }
        if (xmlEAAPayload.getTimezone() != null) {
            claimList.add(getClaim(xmlEAAPayload.getTimezone()));
        }
        if (xmlEAAPayload.getLocale() != null) {
            claimList.add(getClaim(xmlEAAPayload.getLocale()));
        }
        if (xmlEAAPayload.getAddress() != null) {
            claimList.add(getAddressClaim(xmlEAAPayload.getAddress()));
        }
        if (xmlEAAPayload.getPhoneNumber() != null) {
            claimList.add(getClaim(xmlEAAPayload.getPhoneNumber()));
        }
        if (xmlEAAPayload.getPhoneNumberVerified() != null) {
            claimList.add(getClaim(xmlEAAPayload.getPhoneNumberVerified()));
        }
        if (xmlEAAPayload.getPlaceOfBirth() != null) {
            claimList.add(getPlaceOfBirthClaim(xmlEAAPayload.getPlaceOfBirth()));
        }
        if (xmlEAAPayload.getNationalities() != null) {
            claimList.add(getClaim(xmlEAAPayload.getNationalities()));
        }
        if (xmlEAAPayload.getBirthFamilyName() != null) {
            claimList.add(getClaim(xmlEAAPayload.getBirthFamilyName()));
        }
        if (xmlEAAPayload.getBirthGivenName() != null) {
            claimList.add(getClaim(xmlEAAPayload.getBirthGivenName()));
        }
        if (xmlEAAPayload.getBirthMiddleName() != null) {
            claimList.add(getClaim(xmlEAAPayload.getBirthMiddleName()));
        }
        if (xmlEAAPayload.getSalutation() != null) {
            claimList.add(getClaim(xmlEAAPayload.getSalutation()));
        }
        if (xmlEAAPayload.getTitle() != null) {
            claimList.add(getClaim(xmlEAAPayload.getTitle()));
        }
        if (xmlEAAPayload.getMobilePhoneNumber() != null) {
            claimList.add(getClaim(xmlEAAPayload.getMobilePhoneNumber()));
        }
        if (xmlEAAPayload.getPseudonym() != null) {
            claimList.add(getClaim(xmlEAAPayload.getPseudonym()));
        }
        if (xmlEAAPayload.getCredentialSubject() != null) {
            claimList.addAll(getCredentialSubject().getCredentialSubjects());
        }
        if (xmlEAAPayload.getIssuingCountry() != null) {
            claimList.add(getClaim(xmlEAAPayload.getIssuingCountry()));
        }
        if (xmlEAAPayload.getIssuingAuthority() != null) {
            claimList.add(getClaim(xmlEAAPayload.getIssuingAuthority()));
        }
        if (xmlEAAPayload.getDocumentNumber() != null) {
            claimList.add(getClaim(xmlEAAPayload.getDocumentNumber()));
        }
        if (xmlEAAPayload.getPortrait() != null) {
            claimList.add(getClaim(xmlEAAPayload.getPortrait()));
        }
        if (xmlEAAPayload.getDrivingPrivileges() != null) {
            claimList.add(getDrivingPrivilegesClaim(xmlEAAPayload.getDrivingPrivileges()));
        }
        if (xmlEAAPayload.getUNDistinguishingSign() != null) {
            claimList.add(getClaim(xmlEAAPayload.getUNDistinguishingSign()));
        }
        if (xmlEAAPayload.getPersonalAdministrativeNumber() != null) {
            claimList.add(getClaim(xmlEAAPayload.getPersonalAdministrativeNumber()));
        }
        if (xmlEAAPayload.getHeight() != null) {
            claimList.add(getClaim(xmlEAAPayload.getHeight()));
        }
        if (xmlEAAPayload.getWeight() != null) {
            claimList.add(getClaim(xmlEAAPayload.getWeight()));
        }
        if (xmlEAAPayload.getEyeColour() != null) {
            claimList.add(getClaim(xmlEAAPayload.getEyeColour()));
        }
        if (xmlEAAPayload.getHairColour() != null) {
            claimList.add(getClaim(xmlEAAPayload.getHairColour()));
        }
        if (xmlEAAPayload.getResidentPostalAddress() != null) {
            claimList.add(getClaim(xmlEAAPayload.getResidentPostalAddress()));
        }
        if (xmlEAAPayload.getPortraitCaptureDate() != null) {
            claimList.add(getClaim(xmlEAAPayload.getPortraitCaptureDate()));
        }
        if (xmlEAAPayload.getAgeInYears() != null) {
            claimList.add(getClaim(xmlEAAPayload.getAgeInYears()));
        }
        if (xmlEAAPayload.getAgeBirthYear() != null) {
            claimList.add(getClaim(xmlEAAPayload.getAgeBirthYear()));
        }
        if (xmlEAAPayload.getAgeEqualOrOver() != null) {
            claimList.add(getClaim(xmlEAAPayload.getAgeEqualOrOver()));
        }
        if (xmlEAAPayload.getAgeOverNN() != null) {
            for (XmlClaim item : xmlEAAPayload.getAgeOverNN()) {
                claimList.add(getClaim(item));
            }
        }
        if (xmlEAAPayload.getIssuingJurisdiction() != null) {
            claimList.add(getClaim(xmlEAAPayload.getIssuingJurisdiction()));
        }
        if (xmlEAAPayload.getResidentAddressCity() != null) {
            claimList.add(getClaim(xmlEAAPayload.getResidentAddressCity()));
        }
        if (xmlEAAPayload.getResidentAddressState() != null) {
            claimList.add(getClaim(xmlEAAPayload.getResidentAddressState()));
        }
        if (xmlEAAPayload.getResidentAddressPostalCode() != null) {
            claimList.add(getClaim(xmlEAAPayload.getResidentAddressPostalCode()));
        }
        if (xmlEAAPayload.getResidentAddressCountry() != null) {
            claimList.add(getClaim(xmlEAAPayload.getResidentAddressCountry()));
        }
        if (xmlEAAPayload.getBiometricTemplate() != null) {
            for (XmlClaim item : xmlEAAPayload.getBiometricTemplate()) {
                claimList.add(getClaim(item));
            }
        }
        if (xmlEAAPayload.getSignatureUsualMark() != null) {
            claimList.add(getClaim(xmlEAAPayload.getSignatureUsualMark()));
        }
        if (xmlEAAPayload.getFingerprint() != null) {
            claimList.add(getClaim(xmlEAAPayload.getFingerprint()));
        }
        if (xmlEAAPayload.getBusinessName() != null) {
            claimList.add(getClaim(xmlEAAPayload.getBusinessName()));
        }
        if (xmlEAAPayload.getOrganizationName() != null) {
            claimList.add(getClaim(xmlEAAPayload.getOrganizationName()));
        }
        if (xmlEAAPayload.getBirthFullName() != null) {
            claimList.add(getClaim(xmlEAAPayload.getBirthFullName()));
        }
        if (xmlEAAPayload.getProfession() != null) {
            claimList.add(getClaim(xmlEAAPayload.getProfession()));
        }
        if (xmlEAAPayload.getRelationshipFather() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipFather()));
        }
        if (xmlEAAPayload.getRelationshipMother() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipMother()));
        }
        if (xmlEAAPayload.getRelationshipParent() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipParent()));
        }
        if (xmlEAAPayload.getRelationshipSon() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipSon()));
        }
        if (xmlEAAPayload.getRelationshipDaughter() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipDaughter()));
        }
        if (xmlEAAPayload.getRelationshipBrother() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipBrother()));
        }
        if (xmlEAAPayload.getRelationshipSister() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipSister()));
        }
        if (xmlEAAPayload.getRelationshipSibling() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipSibling()));
        }
        if (xmlEAAPayload.getRelationshipSpouse() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipSpouse()));
        }
        if (xmlEAAPayload.getRelationshipFatherInLaw() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipFatherInLaw()));
        }
        if (xmlEAAPayload.getRelationshipMotherInLaw() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipMotherInLaw()));
        }
        if (xmlEAAPayload.getRelationshipParentInLaw() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipParentInLaw()));
        }
        if (xmlEAAPayload.getRelationshipSonInLaw() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipSonInLaw()));
        }
        if (xmlEAAPayload.getRelationshipDaughterInLaw() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipDaughterInLaw()));
        }
        if (xmlEAAPayload.getRelationshipChildInLaw() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipChildInLaw()));
        }
        if (xmlEAAPayload.getRelationshipParentalAuthority() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipParentalAuthority()));
        }
        if (xmlEAAPayload.getRelationshipLegalRepresentative() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipLegalRepresentative()));
        }
        if (xmlEAAPayload.getRelationshipAgent() != null) {
            claimList.add(getClaim(xmlEAAPayload.getRelationshipAgent()));
        }
        if (xmlEAAPayload.getDocumentType() != null) {
            claimList.add(getClaim(xmlEAAPayload.getDocumentType()));
        }
        if (xmlEAAPayload.getAdministrativeIssuanceDate() != null) {
            claimList.add(getClaim(xmlEAAPayload.getAdministrativeIssuanceDate()));
        }
        if (xmlEAAPayload.getAdministrativeExpirationDate() != null) {
            claimList.add(getClaim(xmlEAAPayload.getAdministrativeExpirationDate()));
        }
        if (xmlEAAPayload.getTrustAnchor() != null) {
            claimList.add(getClaim(xmlEAAPayload.getTrustAnchor()));
        }
        if (xmlEAAPayload.getResidentAddressStreet() != null) {
            claimList.add(getClaim(xmlEAAPayload.getResidentAddressStreet()));
        }
        if (xmlEAAPayload.getResidentAddressHouseNumber() != null) {
            claimList.add(getClaim(xmlEAAPayload.getResidentAddressHouseNumber()));
        }
        if (xmlEAAPayload.getIssuingAuthorityRegistrationIdentifier() != null) {
            claimList.add(getClaim(xmlEAAPayload.getIssuingAuthorityRegistrationIdentifier()));
        }
        if (xmlEAAPayload.getOneTimeUse() != null) {
            claimList.add(getClaim(xmlEAAPayload.getOneTimeUse()));
        }
        if (xmlEAAPayload.getShortLived() != null) {
            claimList.add(getClaim(xmlEAAPayload.getShortLived()));
        }
        if (xmlEAAPayload.getEvidence() != null) {
            claimList.add(getClaim(xmlEAAPayload.getEvidence()));
        }
        if (xmlEAAPayload.getAttestedAttributesSubject() != null) {
            claimList.add(getClaim(xmlEAAPayload.getAttestedAttributesSubject()));
        }
        if (xmlEAAPayload.getOtherClaim() != null && !xmlEAAPayload.getOtherClaim().isEmpty()) {
            List<ClaimWrapper> claimWrappers = xmlEAAPayload.getOtherClaim().stream()
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
        return new CredentialSubjectProxy(xmlEAAPayload.getCredentialSubject());
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
