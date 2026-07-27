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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.attestation.mdoc.ETSI194721Headers;
import eu.europa.esig.dss.attestation.mdoc.EUDIPIDHeaders;
import eu.europa.esig.dss.attestation.mdoc.ISO180135Headers;
import eu.europa.esig.dss.attestation.mdoc.ISO232202Headers;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDrivingPrivilege;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * This class is used to provide a proper MdocClaim implementation based on the document type.
 * The class defines default values for some properties, which may not be present on a specific implementation.
 *
 */
public abstract class DefaultMdocClaimsBuilder implements MdocClaimsBuilder {

    /**
     * Default constructor
     */
    protected DefaultMdocClaimsBuilder() {
        // empty
    }

    /**
     * Creates claims for the payload parameters
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @return a list of {@link MdocClaim}s
     */
    public List<MdocClaim> buildClaims(MdocPayloadParameters payloadParameters) {
        final List<MdocClaim> result = new ArrayList<>();

        /* ETSI technical claims */
        addClaim(result, getOneTime(payloadParameters));
        addClaim(result, getShortLived(payloadParameters));
        addClaim(result, getCategory(payloadParameters));

        /* Other selectively disclosable claims */

        MdocClaimParameters selectivelyDisclosable = payloadParameters.selectivelyDisclosable();
        addClaim(result, getIssuanceDate(selectivelyDisclosable));
        addClaim(result, getGivenName(selectivelyDisclosable));
        addClaim(result, getFamilyName(selectivelyDisclosable));
        addClaim(result, getEmail(selectivelyDisclosable));
        addClaim(result, getSex(selectivelyDisclosable));
        addClaim(result, getBirthdate(selectivelyDisclosable));
        addClaim(result, getPhoneNumber(selectivelyDisclosable));
        addClaim(result, getPlaceOfBirth(selectivelyDisclosable));
        addClaim(result, getNationality(selectivelyDisclosable));
        addClaim(result, getNationalities(selectivelyDisclosable));
        addClaim(result, getBirthGivenName(selectivelyDisclosable));
        addClaim(result, getBirthFamilyName(selectivelyDisclosable));
        addClaim(result, getTitle(selectivelyDisclosable));
        addClaim(result, getMobilePhoneNumber(selectivelyDisclosable));
        addClaim(result, getPseudonym(selectivelyDisclosable));
        addClaim(result, getIssuingCountry(selectivelyDisclosable));
        addClaim(result, getIssuingAuthority(selectivelyDisclosable));
        addClaim(result, getDocumentNumber(selectivelyDisclosable));
        addClaim(result, getPortrait(selectivelyDisclosable));
        addClaim(result, getDrivingPrivileges(selectivelyDisclosable));
        addClaim(result, getDistinguishingSign(selectivelyDisclosable));
        addClaim(result, getPersonalAdministrativeNumber(selectivelyDisclosable));
        addClaim(result, getHeight(selectivelyDisclosable));
        addClaim(result, getWeight(selectivelyDisclosable));
        addClaim(result, getEyeColour(selectivelyDisclosable));
        addClaim(result, getHairColour(selectivelyDisclosable));
        addClaim(result, getPostalAddress(selectivelyDisclosable));
        addClaim(result, getPortraitCaptureDate(selectivelyDisclosable));
        addClaim(result, getAgeInYears(selectivelyDisclosable));
        addClaim(result, getAgeBirthYear(selectivelyDisclosable));
        addClaims(result, getAgeOverNN(selectivelyDisclosable));
        addClaim(result, getIssuingJurisdiction(selectivelyDisclosable));
        addClaim(result, getResidentAddressCity(selectivelyDisclosable));
        addClaim(result, getResidentAddressState(selectivelyDisclosable));
        addClaim(result, getResidentAddressPostalCode(selectivelyDisclosable));
        addClaim(result, getResidentAddressCountry(selectivelyDisclosable));
        addClaims(result, getBiometricTemplate(selectivelyDisclosable));
        addClaim(result, getBiometricTemplateFace(selectivelyDisclosable));
        addClaim(result, getSignatureUsualMark(selectivelyDisclosable));
        addClaim(result, getFingerprint(selectivelyDisclosable));
        addClaim(result, getBusinessName(selectivelyDisclosable));
        addClaim(result, getOrganizationName(selectivelyDisclosable));
        addClaim(result, getBirthFullName(selectivelyDisclosable));
        addClaim(result, getProfession(selectivelyDisclosable));
        addClaim(result, getRelationshipFather(selectivelyDisclosable));
        addClaim(result, getRelationshipMother(selectivelyDisclosable));
        addClaim(result, getRelationshipParent(selectivelyDisclosable));
        addClaim(result, getRelationshipSon(selectivelyDisclosable));
        addClaim(result, getRelationshipDaughter(selectivelyDisclosable));
        addClaim(result, getRelationshipBrother(selectivelyDisclosable));
        addClaim(result, getRelationshipSister(selectivelyDisclosable));
        addClaim(result, getRelationshipSibling(selectivelyDisclosable));
        addClaim(result, getRelationshipSpouse(selectivelyDisclosable));
        addClaim(result, getRelationshipFatherInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipMotherInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipParentInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipSonInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipDaughterInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipChildInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipParentalAuthority(selectivelyDisclosable));
        addClaim(result, getRelationshipLegalRepresentative(selectivelyDisclosable));
        addClaim(result, getRelationshipAgent(selectivelyDisclosable));
        addClaim(result, getDocumentType(selectivelyDisclosable));
        addClaim(result, getAdministrativeIssuanceDate(selectivelyDisclosable));
        addClaim(result, getAdministrativeExpirationDate(selectivelyDisclosable));
        addClaim(result, getResidentAddressStreet(selectivelyDisclosable));
        addClaim(result, getResidentAddressHouseNumber(selectivelyDisclosable));
        addClaim(result, getTrustAnchor(selectivelyDisclosable));
        addClaim(result, getIssuingAuthorityRegistrationIdentifier(selectivelyDisclosable));
        addClaim(result, getAttestedAttributesSubject(selectivelyDisclosable));

        result.addAll(selectivelyDisclosable.getOtherClaims());

        return result;
    }

    /**
     * Gets mdoc claim generated for the issuanceDate parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getIssuanceDate(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getIssuanceDate(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the shortLived parameter
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getShortLived(MdocPayloadParameters payloadParameters) {
        return ETSI194721MdocClaimsBuilder.getInstance().getShortLived(payloadParameters);
    }

    /**
     * Gets mdoc claim generated for the oneTime parameter
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getOneTime(MdocPayloadParameters payloadParameters) {
        return ETSI194721MdocClaimsBuilder.getInstance().getOneTime(payloadParameters);
    }

    /**
     * Gets mdoc claim generated for the category parameter
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getCategory(MdocPayloadParameters payloadParameters) {
        return ETSI194721MdocClaimsBuilder.getInstance().getCategory(payloadParameters);
    }

    /**
     * Gets mdoc claim generated for the first name parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getGivenName(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getGivenName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the last name parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getFamilyName(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getFamilyName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the email parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getEmail(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getEmail(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the gender parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getSex(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getSex(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the birthdate parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getBirthdate(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getBirthdate(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the phone number parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getPhoneNumber(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getPhoneNumber(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the place of birth parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getPlaceOfBirth(MdocClaimParameters selectivelyDisclosable) {
        if (selectivelyDisclosable.getPlaceOfBirth() != null) {
            return ISO232201MIDClaimsBuilder.getInstance().getPlaceOfBirth(selectivelyDisclosable);
        }
        if (selectivelyDisclosable.getPlaceOfBirthCountry() != null ||
                selectivelyDisclosable.getPlaceOfBirthLocality() != null ||
                selectivelyDisclosable.getPlaceOfBirthRegion() != null) {
            return EUDIPIDMdocClaimsBuilder.getInstance().getPlaceOfBirth(selectivelyDisclosable);
        }
        return null;
    }

    /**
     * Gets mdoc claim generated for the nationality parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getNationality(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getNationality(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the nationalities parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getNationalities(MdocClaimParameters selectivelyDisclosable) {
        return EUDIPIDMdocClaimsBuilder.getInstance().getNationalities(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the birth first name parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getBirthGivenName(MdocClaimParameters selectivelyDisclosable) {
        return EUDIPIDMdocClaimsBuilder.getInstance().getBirthGivenName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the birth last name parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getBirthFamilyName(MdocClaimParameters selectivelyDisclosable) {
        return EUDIPIDMdocClaimsBuilder.getInstance().getBirthFamilyName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the title parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getTitle(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getTitle(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the mobile phone number parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getMobilePhoneNumber(MdocClaimParameters selectivelyDisclosable) {
        return EUDIPIDMdocClaimsBuilder.getInstance().getMobilePhoneNumber(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the pseudonym parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getPseudonym(MdocClaimParameters selectivelyDisclosable) {
        return ETSI194721MdocClaimsBuilder.getInstance().getPseudonym(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the issuing country parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getIssuingCountry(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getIssuingCountry(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the issuing authority parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getIssuingAuthority(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getIssuingAuthority(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the document number parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getDocumentNumber(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getDocumentNumber(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the portrait parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getPortrait(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getPortrait(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the driving privileges parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getDrivingPrivileges(MdocClaimParameters selectivelyDisclosable) {
        return ISO180135MDLClaimsBuilder.getInstance().getDrivingPrivileges(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the UN distinguishing sign parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getDistinguishingSign(MdocClaimParameters selectivelyDisclosable) {
        return ISO180135MDLClaimsBuilder.getInstance().getDistinguishingSign(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the administrative number parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getPersonalAdministrativeNumber(MdocClaimParameters selectivelyDisclosable) {
        return ISO180135MDLClaimsBuilder.getInstance().getPersonalAdministrativeNumber(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the height parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getHeight(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getHeight(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the weight parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getWeight(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getWeight(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the eye colour parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getEyeColour(MdocClaimParameters selectivelyDisclosable) {
        return ISO180135MDLClaimsBuilder.getInstance().getEyeColour(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the hair colour parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getHairColour(MdocClaimParameters selectivelyDisclosable) {
        return ISO180135MDLClaimsBuilder.getInstance().getHairColour(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident address parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getPostalAddress(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getPostalAddress(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the portrait capture date parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getPortraitCaptureDate(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getPortraitCaptureDate(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the age in years parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getAgeInYears(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getAgeInYears(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the age birth year parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getAgeBirthYear(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getAgeBirthYear(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claims generated for the age over NN parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return a list of {@link MdocClaim}s
     */
    protected List<MdocClaim> getAgeOverNN(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getAgeOverNN(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the issuing jurisdiction parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getIssuingJurisdiction(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getIssuingJurisdiction(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident city parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getResidentAddressCity(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getResidentAddressCity(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident state parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getResidentAddressState(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getResidentAddressState(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident postal code parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getResidentAddressPostalCode(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getResidentAddressPostalCode(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident country parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getResidentAddressCountry(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getResidentAddressCountry(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claims generated for the biometric template parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return a list of {@link MdocClaim}s
     */
    protected List<MdocClaim> getBiometricTemplate(MdocClaimParameters selectivelyDisclosable) {
        return ISO180135MDLClaimsBuilder.getInstance().getBiometricTemplate(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the biometric template face
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getBiometricTemplateFace(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getBiometricTemplateFace(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the signature usual mark parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getSignatureUsualMark(MdocClaimParameters selectivelyDisclosable) {
        return ISO180135MDLClaimsBuilder.getInstance().getSignatureUsualMark(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the fingerprint parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getFingerprint(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getFingerprint(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the business name parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getBusinessName(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getBusinessName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the organization name parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getOrganizationName(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getOrganizationName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the birth full name parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getBirthFullName(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getBirthFullName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the profession parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getProfession(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getProfession(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship father parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipFather(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipFather(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship mother parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipMother(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipMother(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship parent parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipParent(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipParent(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship son parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipSon(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipSon(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship daughter parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipDaughter(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipDaughter(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship brother parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipBrother(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipBrother(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship sister parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipSister(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipSister(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship sibling parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipSibling(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipSibling(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship spouse parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipSpouse(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipSpouse(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship father in law parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipFatherInLaw(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipFatherInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship mother in law parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipMotherInLaw(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipMotherInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship parent in law parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipParentInLaw(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipParentInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship son in law parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipSonInLaw(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipSonInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship daughter in law parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipDaughterInLaw(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipDaughterInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship child in law parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipChildInLaw(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipChildInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship parental authority parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipParentalAuthority(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipParentalAuthority(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship legal representative parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipLegalRepresentative(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipLegalRepresentative(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship agent parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getRelationshipAgent(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getRelationshipAgent(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the document type parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getDocumentType(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getDocumentType(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the administrative issuance date parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getAdministrativeIssuanceDate(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getAdministrativeIssuanceDate(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the administrative expiration date parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getAdministrativeExpirationDate(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getAdministrativeExpirationDate(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident street parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getResidentAddressStreet(MdocClaimParameters selectivelyDisclosable) {
        return ISO232201MIDClaimsBuilder.getInstance().getResidentAddressStreet(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident house number parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getResidentAddressHouseNumber(MdocClaimParameters selectivelyDisclosable) {
        return EUDIPIDMdocClaimsBuilder.getInstance().getResidentAddressHouseNumber(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the trust anchor parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getTrustAnchor(MdocClaimParameters selectivelyDisclosable) {
        return EUDIPIDMdocClaimsBuilder.getInstance().getTrustAnchor(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the issuing authority registration identifier parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getIssuingAuthorityRegistrationIdentifier(MdocClaimParameters selectivelyDisclosable) {
        return ETSI194721MdocClaimsBuilder.getInstance().getIssuingAuthorityRegistrationIdentifier(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the attested attributes subject family name parameter
     *
     * @param selectivelyDisclosable {@link MdocClaimParameters}
     * @return {@link MdocClaim}
     */
    protected MdocClaim getAttestedAttributesSubject(MdocClaimParameters selectivelyDisclosable) {
        return ETSI194721MdocClaimsBuilder.getInstance().getAttestedAttributesSubject(selectivelyDisclosable);
    }

    /**
     * Gets the namespace for the given claims category
     *
     * @return {@link String}
     */
    protected abstract String getNamespace();

    /**
     * Creates a new MdocClaim using the name, value and the applicable namespace
     *
     * @param name {@link String}
     * @param value {@link Object}
     * @return {@link MdocClaim}
     */
    protected MdocClaim create(String name, Object value) {
        return MdocClaim.create(getNamespace(), name, value);
    }

    /**
     * Adds the {@code claim} to the {@code result} list if not null
     *
     * @param result a list of {@link MdocClaim}s
     * @param claim {@link MdocClaim} to be added
     */
    protected void addClaim(final List<MdocClaim> result, MdocClaim claim) {
        if (claim != null) {
            result.add(claim);
        }
    }

    /**
     * Adds the {@code claim} to the {@code result} list if not null
     *
     * @param result a list of {@link MdocClaim}s
     * @param claims a list of {@link MdocClaim}s to be added
     */
    protected void addClaims(final List<MdocClaim> result, List<MdocClaim> claims) {
        if (Utils.isCollectionNotEmpty(claims)) {
            claims.forEach(c -> addClaim(result, c));
        }
    }

    /**
     * Provides claim definitions for the document conformant to ISO/IEC 18013-5 MDL mdoc.
     */
    protected static final class ISO180135MDLClaimsBuilder extends DefaultMdocClaimsBuilder {

        /** Singleton */
        private static ISO180135MDLClaimsBuilder instance;

        /**
         * Default constructor
         */
        private ISO180135MDLClaimsBuilder() {
            // empty
        }

        /**
         * Gets current instance
         *
         * @return {@link ISO180135MDLClaimsBuilder}
         */
        public static ISO180135MDLClaimsBuilder getInstance() {
            if (instance == null) {
                instance = new ISO180135MDLClaimsBuilder();
            }
            return instance;
        }

        @Override
        protected String getNamespace() {
            return MdocConstants.ISO18013_5_NAMESPACE;
        }

        @Override
        protected MdocClaim getIssuanceDate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuanceDate() != null) {
                return create(ISO180135Headers.ISSUE_DATE, selectivelyDisclosable.getIssuanceDate());
            }
            return null;
        }

        @Override
        protected MdocClaim getGivenName(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getGivenName() != null) {
                return create(ISO180135Headers.GIVEN_NAME, selectivelyDisclosable.getGivenName());
            }
            return null;
        }

        @Override
        protected MdocClaim getFamilyName(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getFamilyName() != null) {
                return create(ISO180135Headers.FAMILY_NAME, selectivelyDisclosable.getFamilyName());
            }
            return null;
        }

        @Override
        protected MdocClaim getSex(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getSex() != null) {
                return create(ISO180135Headers.SEX, selectivelyDisclosable.getSex());
            }
            return null;
        }

        @Override
        protected MdocClaim getBirthdate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthdate() != null) {
                if (selectivelyDisclosable.getBirthdateApproximateMask() != null) {
                    return super.getBirthdate(selectivelyDisclosable);
                }
                return create(ISO180135Headers.BIRTH_DATE, CBORUtils.toFullDate(selectivelyDisclosable.getBirthdate()));
            }
            return null;
        }

        @Override
        protected MdocClaim getPlaceOfBirth(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPlaceOfBirth() != null) {
                return create(ISO180135Headers.BIRTH_PLACE, selectivelyDisclosable.getPlaceOfBirth());
            }
            return super.getPlaceOfBirth(selectivelyDisclosable);
        }

        @Override
        protected MdocClaim getNationality(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getNationality() != null) {
                return create(ISO180135Headers.NATIONALITY, selectivelyDisclosable.getNationality());
            }
            return null;
        }

        @Override
        protected MdocClaim getIssuingCountry(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingCountry() != null) {
                return create(ISO180135Headers.ISSUING_COUNTRY, selectivelyDisclosable.getIssuingCountry());
            }
            return null;
        }

        @Override
        protected MdocClaim getIssuingAuthority(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingAuthority() != null) {
                return create(ISO180135Headers.ISSUING_AUTHORITY, selectivelyDisclosable.getIssuingAuthority());
            }
            return null;
        }

        @Override
        protected MdocClaim getDocumentNumber(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getDocumentNumber() != null) {
                return create(ISO180135Headers.LICENCE_NUMBER, selectivelyDisclosable.getDocumentNumber());
            }
            return null;
        }

        @Override
        protected MdocClaim getPortrait(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPortrait() != null) {
                return create(ISO180135Headers.PORTRAIT, selectivelyDisclosable.getPortrait());
            }
            return null;
        }

        @Override
        protected MdocClaim getDrivingPrivileges(MdocClaimParameters selectivelyDisclosable) {
            if (Utils.isCollectionNotEmpty(selectivelyDisclosable.getDrivingPrivileges())) {
                final CBORArray drivingPrivileges = new CBORArray();
                for (MdocDrivingPrivilege mdocDrivingPrivilege : selectivelyDisclosable.getDrivingPrivileges()) {
                    CBORMap drivingPrivilege = new CBORMap();
                    drivingPrivilege.put(ISO180135Headers.DRIVING_PRIVILEGES_VEHICLE_CATEGORY_CODE, mdocDrivingPrivilege.getVehicleCategoryCode());
                    if (mdocDrivingPrivilege.getIssueDate() != null) {
                        drivingPrivilege.put(ISO180135Headers.DRIVING_PRIVILEGES_ISSUE_DATE, CBORUtils.toFullDate(mdocDrivingPrivilege.getIssueDate()));
                    }
                    if (mdocDrivingPrivilege.getExpiryDate() != null) {
                        drivingPrivilege.put(ISO180135Headers.DRIVING_PRIVILEGES_EXPIRY_DATE, CBORUtils.toFullDate(mdocDrivingPrivilege.getExpiryDate()));
                    }
                    if (Utils.isCollectionNotEmpty(mdocDrivingPrivilege.getCodes())) {
                        CBORArray codes = new CBORArray();
                        for (MdocDrivingPrivilege.Code mdocCode : mdocDrivingPrivilege.getCodes()) {
                            CBORMap code = new CBORMap();
                            code.put(ISO180135Headers.DRIVING_PRIVILEGES_CODE_CODE, mdocCode.getCode());
                            if (mdocCode.getSign() != null) {
                                code.put(ISO180135Headers.DRIVING_PRIVILEGES_CODE_SIGN, mdocCode.getSign());
                            }
                            if (mdocCode.getValue() != null) {
                                code.put(ISO180135Headers.DRIVING_PRIVILEGES_CODE_VALUE, mdocCode.getValue());
                            }
                            codes.add(code);
                        }
                    }
                    drivingPrivileges.add(drivingPrivilege);
                }
                return create(ISO180135Headers.DRIVING_PRIVILEGES, drivingPrivileges);
            }
            return null;
        }

        @Override
        protected MdocClaim getDistinguishingSign(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getDistinguishingSign() != null) {
                return create(ISO180135Headers.UN_DISTINGUISHING_SIGN, selectivelyDisclosable.getDistinguishingSign());
            }
            return null;
        }

        @Override
        protected MdocClaim getPersonalAdministrativeNumber(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPersonalAdministrativeNumber() != null) {
                return create(ISO180135Headers.ADMINISTRATIVE_NUMBER, selectivelyDisclosable.getPersonalAdministrativeNumber());
            }
            return null;
        }

        @Override
        protected MdocClaim getHeight(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getHeight() != null) {
                return create(ISO180135Headers.HEIGHT, selectivelyDisclosable.getHeight());
            }
            return null;
        }

        @Override
        protected MdocClaim getWeight(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getWeight() != null) {
                return create(ISO180135Headers.WEIGHT, selectivelyDisclosable.getWeight());
            }
            return null;
        }

        @Override
        protected MdocClaim getEyeColour(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getEyeColour() != null) {
                return create(ISO180135Headers.EYE_COLOUR, selectivelyDisclosable.getEyeColour());
            }
            return null;
        }

        @Override
        protected MdocClaim getHairColour(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getHairColour() != null) {
                return create(ISO180135Headers.HAIR_COLOUR, selectivelyDisclosable.getHairColour());
            }
            return null;
        }

        @Override
        protected MdocClaim getPostalAddress(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPostalAddress() != null) {
                return create(ISO180135Headers.RESIDENT_ADDRESS, selectivelyDisclosable.getPostalAddress());
            }
            return null;
        }

        @Override
        protected MdocClaim getPortraitCaptureDate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPortraitCaptureDate() != null) {
                return create(ISO180135Headers.PORTRAIT_CAPTURE_DATE, selectivelyDisclosable.getPortraitCaptureDate());
            }
            return null;
        }

        @Override
        protected MdocClaim getAgeInYears(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAgeInYears() != null) {
                return create(ISO180135Headers.AGE_IN_YEARS, selectivelyDisclosable.getAgeInYears());
            }
            return null;
        }

        @Override
        protected MdocClaim getAgeBirthYear(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAgeBirthYear() != null) {
                return create(ISO180135Headers.AGE_BIRTH_YEAR, selectivelyDisclosable.getAgeBirthYear());
            }
            return null;
        }

        @Override
        protected List<MdocClaim> getAgeOverNN(MdocClaimParameters selectivelyDisclosable) {
            if (Utils.isMapNotEmpty(selectivelyDisclosable.getAgeOverNN())) {
                final List<MdocClaim> result = new ArrayList<>();
                for (Map.Entry<Integer, Boolean> entry : selectivelyDisclosable.getAgeOverNN().entrySet()) {
                    addClaim(result, create(ISO180135Headers.AGE_OVER_NN + entry.getKey(), entry.getValue()));
                }
                return result;
            }
            return Collections.emptyList();
        }

        @Override
        protected MdocClaim getIssuingJurisdiction(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingJurisdiction() != null) {
                return create(ISO180135Headers.ISSUING_JURISDICTION, selectivelyDisclosable.getIssuingJurisdiction());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressCity(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCity() != null) {
                return create(ISO180135Headers.RESIDENT_CITY, selectivelyDisclosable.getAddressCity());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressState(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressState() != null) {
                return create(ISO180135Headers.RESIDENT_STATE, selectivelyDisclosable.getAddressState());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressPostalCode(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressPostalCode() != null) {
                return create(ISO180135Headers.RESIDENT_POSTAL_CODE, selectivelyDisclosable.getAddressPostalCode());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressCountry(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCountry() != null) {
                return create(ISO180135Headers.RESIDENT_COUNTRY, selectivelyDisclosable.getAddressCountry());
            }
            return null;
        }

        @Override
        protected List<MdocClaim> getBiometricTemplate(MdocClaimParameters selectivelyDisclosable) {
            if (Utils.isMapNotEmpty(selectivelyDisclosable.getBiometricTemplate())) {
                final List<MdocClaim> result = new ArrayList<>();
                for (Map.Entry<String, byte[]> entry : selectivelyDisclosable.getBiometricTemplate().entrySet()) {
                    addClaim(result, create(ISO180135Headers.BIOMETRIC_TEMPLATE_XX + entry.getKey(), entry.getValue()));
                }
                return result;
            }
            return Collections.emptyList();
        }

        @Override
        protected MdocClaim getBiometricTemplateFace(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBiometricTemplateFace() != null) {
                return create(ISO180135Headers.BIOMETRIC_TEMPLATE_FACE, selectivelyDisclosable.getBiometricTemplateFace());
            }
            return null;
        }

        @Override
        protected MdocClaim getSignatureUsualMark(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getSignatureUsualMark() != null) {
                return create(ISO180135Headers.SIGNATURE, selectivelyDisclosable.getSignatureUsualMark());
            }
            return null;
        }

        @Override
        protected MdocClaim getAdministrativeIssuanceDate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeIssuanceDate() != null) {
                return create(ISO180135Headers.ISSUE_DATE, selectivelyDisclosable.getAdministrativeIssuanceDate());
            }
            return null;
        }

        @Override
        protected MdocClaim getAdministrativeExpirationDate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeExpirationDate() != null) {
                return create(ISO180135Headers.EXPIRY_DATE, selectivelyDisclosable.getAdministrativeExpirationDate());
            }
            return null;
        }

    }

    /**
     * Provides claim definitions for the document conformant to ISO/IEC 23220-1 MID mdoc.
     */
    protected static final class ISO232201MIDClaimsBuilder extends DefaultMdocClaimsBuilder {

        /** Singleton */
        private static ISO232201MIDClaimsBuilder instance;

        /**
         * Default constructor
         */
        private ISO232201MIDClaimsBuilder() {
            // empty
        }

        /**
         * Gets current instance
         *
         * @return {@link ISO232201MIDClaimsBuilder}
         */
        public static ISO232201MIDClaimsBuilder getInstance() {
            if (instance == null) {
                instance = new ISO232201MIDClaimsBuilder();
            }
            return instance;
        }

        @Override
        public String getNamespace() {
            return MdocConstants.ISO23220_1_NAMESPACE;
        }

        @Override
        protected MdocClaim getIssuanceDate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuanceDate() != null) {
                return create(ISO232202Headers.ISSUE_DATE, selectivelyDisclosable.getIssuanceDate());
            }
            return null;
        }

        @Override
        protected MdocClaim getGivenName(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getGivenName() != null) {
                return create(ISO232202Headers.GIVEN_NAME, selectivelyDisclosable.getGivenName());
            }
            return null;
        }

        @Override
        protected MdocClaim getFamilyName(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getFamilyName() != null) {
                return create(ISO232202Headers.FAMILY_NAME, selectivelyDisclosable.getFamilyName());
            }
            return null;
        }

        @Override
        protected MdocClaim getEmail(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getEmail() != null) {
                return create(ISO232202Headers.EMAIL_ADDRESS, selectivelyDisclosable.getEmail());
            }
            return null;
        }

        @Override
        protected MdocClaim getSex(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getSex() != null) {
                return create(ISO232202Headers.SEX, selectivelyDisclosable.getSex());
            }
            return null;
        }

        @Override
        protected MdocClaim getBirthdate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthdate() != null) {
                final CBORMap birthdate = new CBORMap();
                birthdate.put(ISO232202Headers.BIRTH_DATE, CBORUtils.toFullDate(selectivelyDisclosable.getBirthdate()));
                if (selectivelyDisclosable.getBirthdateApproximateMask() != null) {
                    birthdate.put(ISO232202Headers.APPROXIMATE_MASK, selectivelyDisclosable.getBirthdateApproximateMask());
                }
                return create(ISO232202Headers.BIRTH_DATE, birthdate);
            }
            return null;
        }

        @Override
        protected MdocClaim getPhoneNumber(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPhoneNumber() != null) {
                return create(ISO232202Headers.TELEPHONE_NUMBER, selectivelyDisclosable.getPhoneNumber());
            }
            return null;
        }

        @Override
        protected MdocClaim getPlaceOfBirth(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPlaceOfBirth() != null) {
                return create(ISO232202Headers.BIRTHPLACE, selectivelyDisclosable.getPlaceOfBirth());
            }
            return super.getPlaceOfBirth(selectivelyDisclosable);
        }

        @Override
        protected MdocClaim getNationality(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getNationality() != null) {
                return create(ISO232202Headers.NATIONALITY, selectivelyDisclosable.getNationality());
            }
            return null;
        }

        @Override
        protected MdocClaim getTitle(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getTitle() != null) {
                return create(ISO232202Headers.TITLE, selectivelyDisclosable.getTitle());
            }
            return null;
        }

        @Override
        protected MdocClaim getIssuingCountry(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingCountry() != null) {
                return create(ISO232202Headers.ISSUING_COUNTRY, selectivelyDisclosable.getIssuingCountry());
            }
            return null;
        }

        @Override
        protected MdocClaim getIssuingAuthority(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingAuthority() != null) {
                return create(ISO232202Headers.ISSUING_AUTHORITY, selectivelyDisclosable.getIssuingAuthority());
            }
            return null;
        }

        @Override
        protected MdocClaim getDocumentNumber(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getDocumentNumber() != null) {
                return create(ISO232202Headers.DOCUMENT_NUMBER, selectivelyDisclosable.getDocumentNumber());
            }
            return null;
        }

        @Override
        protected MdocClaim getPortrait(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPortrait() != null) {
                return create(ISO232202Headers.PORTRAIT, selectivelyDisclosable.getPortrait());
            }
            return null;
        }

        @Override
        protected MdocClaim getHeight(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getHeight() != null) {
                return create(ISO232202Headers.HEIGHT, selectivelyDisclosable.getHeight());
            }
            return null;
        }

        @Override
        protected MdocClaim getWeight(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getWeight() != null) {
                return create(ISO232202Headers.WEIGHT, selectivelyDisclosable.getWeight());
            }
            return null;
        }

        @Override
        protected MdocClaim getPostalAddress(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPostalAddress() != null) {
                return create(ISO232202Headers.RESIDENT_ADDRESS, selectivelyDisclosable.getPostalAddress());
            }
            return null;
        }

        @Override
        protected MdocClaim getPortraitCaptureDate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPortraitCaptureDate() != null) {
                return create(ISO232202Headers.PORTRAIT_CAPTURE_DATE, selectivelyDisclosable.getPortraitCaptureDate());
            }
            return null;
        }

        @Override
        protected MdocClaim getAgeInYears(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAgeInYears() != null) {
                return create(ISO232202Headers.AGE_IN_YEARS, selectivelyDisclosable.getAgeInYears());
            }
            return null;
        }

        @Override
        protected MdocClaim getAgeBirthYear(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAgeBirthYear() != null) {
                return create(ISO232202Headers.AGE_BIRTH_YEAR, selectivelyDisclosable.getAgeBirthYear());
            }
            return null;
        }

        @Override
        protected List<MdocClaim> getAgeOverNN(MdocClaimParameters selectivelyDisclosable) {
            if (Utils.isMapNotEmpty(selectivelyDisclosable.getAgeOverNN())) {
                final List<MdocClaim> result = new ArrayList<>();
                for (Map.Entry<Integer, Boolean> entry : selectivelyDisclosable.getAgeOverNN().entrySet()) {
                    addClaim(result, create(ISO232202Headers.AGE_OVER_NN + entry.getKey(), entry.getValue()));
                }
                return result;
            }
            return Collections.emptyList();
        }

        @Override
        protected MdocClaim getIssuingJurisdiction(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingJurisdiction() != null) {
                return create(ISO232202Headers.ISSUING_SUBDIVISION, selectivelyDisclosable.getIssuingJurisdiction());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressCity(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCity() != null) {
                return create(ISO232202Headers.RESIDENT_CITY, selectivelyDisclosable.getAddressCity());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressPostalCode(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressPostalCode() != null) {
                return create(ISO232202Headers.RESIDENT_POSTAL_CODE, selectivelyDisclosable.getAddressPostalCode());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressCountry(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCountry() != null) {
                return create(ISO232202Headers.RESIDENT_COUNTRY, selectivelyDisclosable.getAddressCountry());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressState(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressState() != null) {
                return create(ISO232202Headers.RESIDENT_STATE, selectivelyDisclosable.getAddressState());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressStreet(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressStreet() != null) {
                return create(ISO232202Headers.RESIDENT_STREET, selectivelyDisclosable.getAddressStreet());
            }
            return null;
        }

        @Override
        protected MdocClaim getBiometricTemplateFace(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBiometricTemplateFace() != null) {
                return create(ISO232202Headers.BIOMETRIC_TEMPLATE_FACE, selectivelyDisclosable.getBiometricTemplateFace());
            }
            return null;
        }

        @Override
        protected MdocClaim getFingerprint(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getSignatureUsualMark() != null) {
                return create(ISO232202Headers.FINGERPRINT, selectivelyDisclosable.getFingerprint());
            }
            return null;
        }

        @Override
        protected MdocClaim getBusinessName(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBusinessName() != null) {
                return create(ISO232202Headers.BUSINESS_NAME, selectivelyDisclosable.getBusinessName());
            }
            return null;
        }

        @Override
        protected MdocClaim getOrganizationName(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getOrganizationName() != null) {
                return create(ISO232202Headers.ORGANIZATION_NAME, selectivelyDisclosable.getOrganizationName());
            }
            return null;
        }

        @Override
        protected MdocClaim getBirthFullName(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthFullName() != null) {
                return create(ISO232202Headers.NAME_AT_BIRTH, selectivelyDisclosable.getBirthFullName());
            }
            return null;
        }

        @Override
        protected MdocClaim getProfession(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getProfession() != null) {
                return create(ISO232202Headers.PROFESSION, selectivelyDisclosable.getProfession());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipFather(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipFather() != null) {
                return create(ISO232202Headers.RELATIONSHIP_FATHER, selectivelyDisclosable.getRelationshipFather());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipMother(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipMother() != null) {
                return create(ISO232202Headers.RELATIONSHIP_MOTHER, selectivelyDisclosable.getRelationshipMother());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipParent(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipParent() != null) {
                return create(ISO232202Headers.RELATIONSHIP_PARENT, selectivelyDisclosable.getRelationshipParent());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipSon(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipSon() != null) {
                return create(ISO232202Headers.RELATIONSHIP_SON, selectivelyDisclosable.getRelationshipSon());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipDaughter(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipDaughter() != null) {
                return create(ISO232202Headers.RELATIONSHIP_DAUGHTER, selectivelyDisclosable.getRelationshipDaughter());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipBrother(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipBrother() != null) {
                return create(ISO232202Headers.RELATIONSHIP_BROTHER, selectivelyDisclosable.getRelationshipBrother());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipSister(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipSister() != null) {
                return create(ISO232202Headers.RELATIONSHIP_SISTER, selectivelyDisclosable.getRelationshipSister());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipSibling(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipSibling() != null) {
                return create(ISO232202Headers.RELATIONSHIP_SIBLING, selectivelyDisclosable.getRelationshipSibling());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipSpouse(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipSpouse() != null) {
                return create(ISO232202Headers.RELATIONSHIP_SPOUSE, selectivelyDisclosable.getRelationshipSpouse());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipFatherInLaw(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipFatherInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_FATHER_IN_LAW, selectivelyDisclosable.getRelationshipFatherInLaw());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipMotherInLaw(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipMotherInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_MOTHER_IN_LAW, selectivelyDisclosable.getRelationshipMotherInLaw());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipParentInLaw(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipParentInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_PARENT_IN_LAW, selectivelyDisclosable.getRelationshipParentInLaw());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipSonInLaw(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipSonInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_SON_IN_LAW, selectivelyDisclosable.getRelationshipSonInLaw());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipDaughterInLaw(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipDaughterInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_DAUGHTER_IN_LAW, selectivelyDisclosable.getRelationshipDaughterInLaw());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipChildInLaw(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipChildInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_CHILD_IN_LAW, selectivelyDisclosable.getRelationshipChildInLaw());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipParentalAuthority(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipParentalAuthority() != null) {
                return create(ISO232202Headers.RELATIONSHIP_PARENTAL_AUTHORITY, selectivelyDisclosable.getRelationshipParentalAuthority());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipLegalRepresentative(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipLegalRepresentative() != null) {
                return create(ISO232202Headers.RELATIONSHIP_LEGAL_REPRESENTATIVE, selectivelyDisclosable.getRelationshipLegalRepresentative());
            }
            return null;
        }

        @Override
        protected MdocClaim getRelationshipAgent(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipAgent() != null) {
                return create(ISO232202Headers.RELATIONSHIP_AGENT, selectivelyDisclosable.getRelationshipAgent());
            }
            return null;
        }

        @Override
        protected MdocClaim getDocumentType(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getDocumentType() != null) {
                return create(ISO232202Headers.DOCUMENT_TYPE, selectivelyDisclosable.getDocumentType());
            }
            return null;
        }

        @Override
        protected MdocClaim getAdministrativeIssuanceDate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeIssuanceDate() != null) {
                return create(ISO232202Headers.ISSUE_DATE, CBORUtils.toFullDate(selectivelyDisclosable.getAdministrativeIssuanceDate()));
            }
            return null;
        }

        @Override
        protected MdocClaim getAdministrativeExpirationDate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeExpirationDate() != null) {
                return create(ISO232202Headers.EXPIRY_DATE, CBORUtils.toFullDate(selectivelyDisclosable.getAdministrativeExpirationDate()));
            }
            return null;
        }

    }

    /**
     * Provides claim definitions for the document conformant to PID Rulebook specification.
     */
    protected static final class EUDIPIDMdocClaimsBuilder extends DefaultMdocClaimsBuilder {

        /** Singleton */
        private static EUDIPIDMdocClaimsBuilder instance;

        /**
         * Default constructor
         */
        private EUDIPIDMdocClaimsBuilder() {
            // empty
        }

        /**
         * Gets current instance
         *
         * @return {@link EUDIPIDMdocClaimsBuilder}
         */
        public static EUDIPIDMdocClaimsBuilder getInstance() {
            if (instance == null) {
                instance = new EUDIPIDMdocClaimsBuilder();
            }
            return instance;
        }

        @Override
        public String getNamespace() {
            return MdocConstants.EUDI_PID_NAMESPACE;
        }

        @Override
        protected MdocClaim getGivenName(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getGivenName() != null) {
                return create(EUDIPIDHeaders.GIVEN_NAME, selectivelyDisclosable.getGivenName());
            }
            return null;
        }

        @Override
        protected MdocClaim getFamilyName(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getFamilyName() != null) {
                return create(EUDIPIDHeaders.FAMILY_NAME, selectivelyDisclosable.getFamilyName());
            }
            return null;
        }

        @Override
        protected MdocClaim getEmail(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getEmail() != null) {
                return create(EUDIPIDHeaders.EMAIL_ADDRESS, selectivelyDisclosable.getEmail());
            }
            return null;
        }

        @Override
        protected MdocClaim getSex(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getSex() != null) {
                return create(EUDIPIDHeaders.SEX, selectivelyDisclosable.getSex());
            }
            return null;
        }

        @Override
        protected MdocClaim getBirthdate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthdate() != null) {
                if (selectivelyDisclosable.getBirthdateApproximateMask() != null) {
                    return super.getBirthdate(selectivelyDisclosable);
                }
                return create(EUDIPIDHeaders.BIRTH_DATE, CBORUtils.toFullDate(selectivelyDisclosable.getBirthdate()));
            }
            return null;
        }

        @Override
        protected MdocClaim getPlaceOfBirth(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPlaceOfBirthCountry() != null ||
                    selectivelyDisclosable.getPlaceOfBirthRegion() != null ||
                    selectivelyDisclosable.getPlaceOfBirthLocality() != null) {
                final CBORMap placeOfBirth = new CBORMap();
                if (selectivelyDisclosable.getPlaceOfBirthCountry() != null) {
                    placeOfBirth.put(EUDIPIDHeaders.PLACE_OF_BIRTH_COUNTRY, selectivelyDisclosable.getPlaceOfBirthCountry());
                }
                if (selectivelyDisclosable.getPlaceOfBirthRegion() != null) {
                    placeOfBirth.put(EUDIPIDHeaders.PLACE_OF_BIRTH_REGION, selectivelyDisclosable.getPlaceOfBirthRegion());
                }
                if (selectivelyDisclosable.getPlaceOfBirthLocality() != null) {
                    placeOfBirth.put(EUDIPIDHeaders.PLACE_OF_BIRTH_LOCALITY, selectivelyDisclosable.getPlaceOfBirthLocality());
                }
                return create(EUDIPIDHeaders.PLACE_OF_BIRTH, placeOfBirth);
            }
            return super.getPlaceOfBirth(selectivelyDisclosable);
        }

        @Override
        protected MdocClaim getNationalities(MdocClaimParameters selectivelyDisclosable) {
            if (Utils.isCollectionNotEmpty(selectivelyDisclosable.getNationalities())) {
                return create(EUDIPIDHeaders.NATIONALITY, selectivelyDisclosable.getNationalities());
            }
            return null;
        }

        @Override
        protected MdocClaim getBirthGivenName(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthGivenName() != null) {
                return create(EUDIPIDHeaders.GIVEN_NAME_BIRTH, selectivelyDisclosable.getBirthGivenName());
            }
            return null;
        }

        @Override
        protected MdocClaim getBirthFamilyName(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthFamilyName() != null) {
                return create(EUDIPIDHeaders.FAMILY_NAME_BIRTH, selectivelyDisclosable.getBirthFamilyName());
            }
            return null;
        }

        @Override
        protected MdocClaim getMobilePhoneNumber(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getMobilePhoneNumber() != null) {
                return create(EUDIPIDHeaders.MOBILE_PHONE_NUMBER, selectivelyDisclosable.getMobilePhoneNumber());
            }
            return null;
        }

        @Override
        protected MdocClaim getIssuingCountry(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingCountry() != null) {
                return create(EUDIPIDHeaders.ISSUING_COUNTRY, selectivelyDisclosable.getIssuingCountry());
            }
            return null;
        }

        @Override
        protected MdocClaim getIssuingAuthority(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingAuthority() != null) {
                return create(EUDIPIDHeaders.ISSUING_AUTHORITY, selectivelyDisclosable.getIssuingAuthority());
            }
            return null;
        }

        @Override
        protected MdocClaim getDocumentNumber(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getDocumentNumber() != null) {
                return create(EUDIPIDHeaders.DOCUMENT_NUMBER, selectivelyDisclosable.getDocumentNumber());
            }
            return null;
        }

        @Override
        protected MdocClaim getPortrait(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPortrait() != null) {
                return create(EUDIPIDHeaders.PORTRAIT, selectivelyDisclosable.getPortrait());
            }
            return null;
        }

        @Override
        protected MdocClaim getPersonalAdministrativeNumber(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPersonalAdministrativeNumber() != null) {
                return create(EUDIPIDHeaders.PERSONAL_ADMINISTRATIVE_NUMBER, selectivelyDisclosable.getPersonalAdministrativeNumber());
            }
            return null;
        }

        @Override
        protected MdocClaim getPostalAddress(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPostalAddress() != null) {
                return create(EUDIPIDHeaders.RESIDENT_ADDRESS, selectivelyDisclosable.getPostalAddress());
            }
            return null;
        }

        @Override
        protected MdocClaim getIssuingJurisdiction(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingJurisdiction() != null) {
                return create(EUDIPIDHeaders.ISSUING_JURISDICTION, selectivelyDisclosable.getIssuingJurisdiction());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressCity(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCity() != null) {
                return create(EUDIPIDHeaders.RESIDENT_CITY, selectivelyDisclosable.getAddressCity());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressState(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressState() != null) {
                return create(EUDIPIDHeaders.RESIDENT_STATE, selectivelyDisclosable.getAddressState());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressPostalCode(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressPostalCode() != null) {
                return create(EUDIPIDHeaders.RESIDENT_POSTAL_CODE, selectivelyDisclosable.getAddressPostalCode());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressCountry(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCountry() != null) {
                return create(EUDIPIDHeaders.RESIDENT_COUNTRY, selectivelyDisclosable.getAddressCountry());
            }
            return null;
        }

        @Override
        protected MdocClaim getAdministrativeIssuanceDate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeIssuanceDate() != null) {
                return create(EUDIPIDHeaders.ISSUANCE_DATE, selectivelyDisclosable.getAdministrativeIssuanceDate());
            }
            return null;
        }

        @Override
        protected MdocClaim getAdministrativeExpirationDate(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeExpirationDate() != null) {
                return create(EUDIPIDHeaders.EXPIRY_DATE, selectivelyDisclosable.getAdministrativeExpirationDate());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressStreet(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressStreet() != null) {
                return create(EUDIPIDHeaders.RESIDENT_STREET, selectivelyDisclosable.getAddressStreet());
            }
            return null;
        }

        @Override
        protected MdocClaim getResidentAddressHouseNumber(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressHouseNumber() != null) {
                return create(EUDIPIDHeaders.RESIDENT_HOUSE_NUMBER, selectivelyDisclosable.getAddressHouseNumber());
            }
            return null;
        }

        @Override
        protected MdocClaim getTrustAnchor(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getTrustAnchor() != null) {
                return create(EUDIPIDHeaders.TRUST_ANCHOR, selectivelyDisclosable.getTrustAnchor());
            }
            return null;
        }

    }

    /**
     * Provides claim definitions for the document conformant to PID Rulebook specification.
     */
    protected static final class ETSI194721MdocClaimsBuilder extends DefaultMdocClaimsBuilder {

        /** Singleton */
        private static ETSI194721MdocClaimsBuilder instance;

        /**
         * Default constructor
         */
        private ETSI194721MdocClaimsBuilder() {
            // empty
        }

        /**
         * Gets current instance
         *
         * @return {@link ETSI194721MdocClaimsBuilder}
         */
        public static ETSI194721MdocClaimsBuilder getInstance() {
            if (instance == null) {
                instance = new ETSI194721MdocClaimsBuilder();
            }
            return instance;
        }

        @Override
        public String getNamespace() {
            return MdocConstants.ETSI_19472_1_NAMESPACE;
        }

        @Override
        protected MdocClaim getShortLived(MdocPayloadParameters payloadParameters) {
            if (payloadParameters.isShortLived()) {
                return create(ETSI194721Headers.SHORT_LIVED, payloadParameters.isShortLived());
            }
            return null;
        }


        @Override
        protected MdocClaim getOneTime(MdocPayloadParameters payloadParameters) {
            if (payloadParameters.isOneTime()) {
                return create(ETSI194721Headers.ONE_TIME, payloadParameters.isOneTime());
            }
            return null;
        }

        @Override
        protected MdocClaim getCategory(MdocPayloadParameters payloadParameters) {
            if (payloadParameters.getCategory() != null) {
                return create(ETSI194721Headers.CATEGORY, payloadParameters.getCategory());
            }
            return null;
        }

        @Override
        protected MdocClaim getPseudonym(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPseudonym() != null) {
                return create(ETSI194721Headers.ALSO_KNOWN_AS, selectivelyDisclosable.getPseudonym());
            }
            return null;
        }

        @Override
        protected MdocClaim getIssuingAuthorityRegistrationIdentifier(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingAuthorityRegistrationIdentifier() != null) {
                return create(ETSI194721Headers.ISSUING_REGISTRATION_IDENTIFIER, selectivelyDisclosable.getIssuingAuthorityRegistrationIdentifier());
            }
            return null;
        }

        @Override
        protected MdocClaim getAttestedAttributesSubject(MdocClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAttestedAttributesSubjectFamilyName() != null &&
                    selectivelyDisclosable.getAttestedAttributesSubjectGivenName() != null &&
                    selectivelyDisclosable.getAttestedAttributesSubjectDocumentNumber() != null) {
                final CBORMap subAttr = new CBORMap();
                CBORMap subId = new CBORMap();
                subId.put(ETSI194721Headers.SUB_ATTRS_ID_FAMILY_NAME, selectivelyDisclosable.getAttestedAttributesSubjectFamilyName());
                subId.put(ETSI194721Headers.SUB_ATTRS_ID_GIVEN_NAME, selectivelyDisclosable.getAttestedAttributesSubjectGivenName());
                subId.put(ETSI194721Headers.SUB_ATTRS_ID_DOCUMENT_NUMBER, selectivelyDisclosable.getAttestedAttributesSubjectDocumentNumber());
                subAttr.put(ETSI194721Headers.SUB_ATTRS_ID, subId);
                return create(ETSI194721Headers.SUB_ATTRS, subAttr);

            } else if (selectivelyDisclosable.getAttestedAttributesSubjectPseudonym() != null) {
                final CBORMap subAttr = new CBORMap();
                subAttr.put(ETSI194721Headers.SUB_ATTRS_AKA, selectivelyDisclosable.getAttestedAttributesSubjectPseudonym());
                return create(ETSI194721Headers.SUB_ATTRS, subAttr);
            }
            return null;
        }

    }

}
