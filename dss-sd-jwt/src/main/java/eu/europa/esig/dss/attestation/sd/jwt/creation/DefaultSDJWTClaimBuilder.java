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

import eu.europa.esig.dss.attestation.common.creation.TokenStatusList;
import eu.europa.esig.dss.attestation.common.key.PublicKeyInfo;
import eu.europa.esig.dss.attestation.common.key.PublicKeyInfoFactory;
import eu.europa.esig.dss.attestation.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.attestation.sd.jwt.key.JWKClaimBuilder;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Default implementation of {@link SDJWTEAAClaimBuilder}
 */
public class DefaultSDJWTClaimBuilder implements SDJWTEAAClaimBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultSDJWTClaimBuilder.class);

    /**
     * The factory is used to build a representation of a public key from a {@code java.security.PublicKey}
     * Default : {@code DefaultPublicKeyInfoFactory}
     */
    private PublicKeyInfoFactory publicKeyInfoFactory;

    /**
     * Default constructor
     */
    public DefaultSDJWTClaimBuilder() {
        // empty
    }

    @Override
    public void setPublicKeyInfoFactory(PublicKeyInfoFactory publicKeyInfoFactory) {
        this.publicKeyInfoFactory = publicKeyInfoFactory;
    }

    @Override
    public List<SDJWTClaim> buildClaims(final SDJWTPayloadParameters payloadParameters) {
        final SDJWTClaimParameters nonSd = payloadParameters.nonSelectivelyDisclosable();
        final SDJWTClaimParameters sd = payloadParameters.selectivelyDisclosable();

        final List<SDJWTClaim> nonSelectivelyDisclosableClaims = buildClaims(nonSd, false);
        final List<SDJWTClaim> selectivelyDisclosableClaims = buildClaims(sd, true);

        ensureNoDuplicateClaimNames(nonSelectivelyDisclosableClaims, selectivelyDisclosableClaims);

        final List<SDJWTClaim> claims = new ArrayList<>();
        claims.addAll(buildTechnicalClaims(payloadParameters));
        claims.addAll(nonSelectivelyDisclosableClaims);
        claims.addAll(selectivelyDisclosableClaims);

        return claims;
    }

    /**
     * Builds technical claims (non-selectively disclosable)
     *
     * @param payloadParameters {@link SDJWTPayloadParameters}
     * @return a list of {@link SDJWTClaim}s
     */
    protected List<SDJWTClaim> buildTechnicalClaims(final SDJWTPayloadParameters payloadParameters) {
        final List<SDJWTClaim> claims = new ArrayList<>();

        addIfNotNull(claims, buildIssuerClaim(payloadParameters));
        addIfNotNull(claims, buildNotBeforeClaim(payloadParameters));
        addIfNotNull(claims, buildExpirationTimeClaim(payloadParameters));
        addIfNotNull(claims, buildOneTimeClaim(payloadParameters));
        addIfNotNull(claims, buildShortLivedClaim(payloadParameters));
        addIfNotNull(claims, buildCategoryClaim(payloadParameters));
        addIfNotNull(claims, buildStatusClaim(payloadParameters));
        addIfNotNull(claims, buildDeviceKeyClaim(payloadParameters));
        addIfNotNull(claims, buildVerifiableCredentialsTypeClaim(payloadParameters));
        addIfNotNull(claims, buildVerifiableCredentialsIntegrityClaim(payloadParameters));

        return claims;
    }

    /**
     * Builds claims for the parameters configuration
     *
     * @param parameters {@link SDJWTClaimParameters}
     * @param selectivelyDisclosable whether the claims are to be made selectively disclosable
     * @return a list of {@link SDJWTClaim}s
     */
    protected List<SDJWTClaim> buildClaims(final SDJWTClaimParameters parameters,
                                           final boolean selectivelyDisclosable) {
        final List<SDJWTClaim> claims = new ArrayList<>();
        addIfNotNull(claims, buildIssuedAtClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildSubjectClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildFamilyNameClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildGivenNameClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildBirthDateClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildNationalitiesClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildAddressClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildEmailClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildPhoneNumberClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildPictureClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildNicknameClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildPreferredNicknameClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildNameClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildMiddleNameClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildProfileClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildWebsiteClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildEmailVerifiedClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildGenderClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildZoneinfoClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildLocaleClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildPhoneNumberVerifiedClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildUpdatedAtClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildPlaceOfBirthClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildBirthFamilyNameClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildBirthGivenNameClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildBirthMiddleNameClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildSalutationClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildTitleClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildMobilePhoneNumberClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildPseudonymClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildDateOfExpiryClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildDateOfIssuanceClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildPersonalAdministrativeNumberClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildSexClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildIssuingAuthorityClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildIssuingCountryClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildDocumentNumberClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildIssuingJurisdictionClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildAgeInYearsClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildAgeBirthYearClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildTrustAnchorClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildAgeEqualOrOverClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildIssuingRegistrationIdentifierClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildAdministrativeValidityNotBeforeClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildAdministrativeValidityExpiryClaim(parameters, selectivelyDisclosable));
        addIfNotNull(claims, buildAttestedAttributesSubject(parameters, selectivelyDisclosable));
        if (Utils.isCollectionNotEmpty(parameters.getOtherClaims())) {
            // selectively discloseness is to be chosen based on the upper parameters
            claims.addAll(parameters.getOtherClaims().stream()
                    .map(c -> ensureSelectedSelectiveDisclosureType(c, selectivelyDisclosable)).collect(Collectors.toList()));
        }
        return claims;
    }

    private SDJWTClaim ensureSelectedSelectiveDisclosureType(SDJWTClaim claim, boolean selectiveDisclosure) {
        if (claim instanceof SDJWTClaimArray) {
            return new SDJWTClaimArray(claim.getName(), ((SDJWTClaimArray) claim).getElements(), selectiveDisclosure, claim.getSalt());
        } else if (claim instanceof SDJWTClaimObject) {
            return new SDJWTClaimObject(claim.getName(), ((SDJWTClaimObject) claim).getChildren(), selectiveDisclosure, claim.getSalt());
        } else {
            return new SDJWTClaim(claim.getName(), claim.getValue(), selectiveDisclosure, claim.getSalt());
        }
    }

    /**
     * Verifies whether the configuration does not contain duplicated claim names
     *
     * @param nonSelectivelyDisclosableClaims a list of non-selectively disclosable {@link SDJWTClaim}s
     * @param selectivelyDisclosableClaims a list of selectively disclosable {@link SDJWTClaim}s
     */
    protected void ensureNoDuplicateClaimNames(final List<SDJWTClaim> nonSelectivelyDisclosableClaims,
                                               final List<SDJWTClaim> selectivelyDisclosableClaims) {
        final Set<String> nonSelectivelyDisclosableClaimNames = new HashSet<>();
        for (SDJWTClaim claim : nonSelectivelyDisclosableClaims) {
            if (claim.getName() != null) {
                nonSelectivelyDisclosableClaimNames.add(claim.getName());
            }
        }

        for (SDJWTClaim claim : selectivelyDisclosableClaims) {
            final String claimName = claim.getName();
            if (claimName != null && nonSelectivelyDisclosableClaimNames.contains(claimName)) {
                throw new IllegalArgumentException(String.format("The claim '%s' cannot be both selectively disclosable and non-selectively disclosable", claimName));
            }
        }
    }

    /**
     * Builds the issuer claim.
     *
     * @param payloadParameters the payload parameters
     * @return the claim or null
     */
    protected SDJWTClaim buildIssuerClaim(final SDJWTPayloadParameters payloadParameters) {
        if (payloadParameters.getIssuer() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.ISSUER, payloadParameters.getIssuer(), false);
    }

    /**
     * Builds the not before claim.
     *
     * @param payloadParameters the payload parameters
     * @return the claim or null
     */
    protected SDJWTClaim buildNotBeforeClaim(final SDJWTPayloadParameters payloadParameters) {
        if (payloadParameters.getNotBeforeDate() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.NOT_BEFORE,
                DSSUtils.getTimeValueInSeconds(payloadParameters.getNotBeforeDate().getTime()), false);
    }

    /**
     * Builds the expiration time claim.
     *
     * @param payloadParameters the payload parameters
     * @return the claim or null
     */
    protected SDJWTClaim buildExpirationTimeClaim(final SDJWTPayloadParameters payloadParameters) {
        if (payloadParameters.getExpirationDate() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.EXPIRATION_TIME,
                DSSUtils.getTimeValueInSeconds(payloadParameters.getExpirationDate().getTime()), false);
    }

    /**
     * Builds the one time claim.
     *
     * @param payloadParameters the payload parameters
     * @return the claim or null
     */
    protected SDJWTClaim buildOneTimeClaim(final SDJWTPayloadParameters payloadParameters) {
        if (!payloadParameters.isOneTime()) {
            return null;
        }
        return buildClaim(SDJWTConstants.ONE_TIME, null, false);
    }

    /**
     * Builds the short lived claim.
     *
     * @param payloadParameters the payload parameters
     * @return the claim or null
     */
    protected SDJWTClaim buildShortLivedClaim(final SDJWTPayloadParameters payloadParameters) {
        if (!payloadParameters.isShortLived()) {
            return null;
        }
        return buildClaim(SDJWTConstants.SHORT_LIVED, null, false);
    }

    /**
     * Builds the category claim.
     *
     * @param payloadParameters the payload parameters
     * @return the claim or null
     */
    protected SDJWTClaim buildCategoryClaim(SDJWTPayloadParameters payloadParameters) {
        if (payloadParameters.getCategory() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.CATEGORY, payloadParameters.getCategory(), false);
    }

    /**
     * Builds a "revocation" claim a per draft-ietf-oauth-revocation-list-13
     *
     * @param payloadParameters the payload parameters
     * @return the claim or null
     */
    protected SDJWTClaim buildStatusClaim(SDJWTPayloadParameters payloadParameters) {
        if (payloadParameters.getStatusList() == null) {
            return null;
        }

        SDJWTClaimObject claim = new SDJWTClaimObject(SDJWTConstants.STATUS, false);

        TokenStatusList tokenStatusList = payloadParameters.getStatusList();
        if (tokenStatusList instanceof ETSITokenStatusList) {
            LOG.debug("Status list is created as per ETSI TS 119 472-1 v1.2.1 definition.");
            ETSITokenStatusList etsiEAAStatusList = (ETSITokenStatusList) tokenStatusList;
            claim.addChild(SDJWTClaim.create(SDJWTConstants.STATUS_TYPE, etsiEAAStatusList.getType()));
            claim.addChild(SDJWTClaim.create(SDJWTConstants.STATUS_PURPOSE, etsiEAAStatusList.getPurpose()));
            claim.addChild(SDJWTClaim.create(SDJWTConstants.STATUS_INDEX, etsiEAAStatusList.getIndex()));
            claim.addChild(SDJWTClaim.create(SDJWTConstants.STATUS_URI, etsiEAAStatusList.getUri()));
            if (etsiEAAStatusList.getCertificate() != null) {
                claim.addChild(SDJWTClaim.create(SDJWTConstants.STATUS_LIST_CERTIFICATE, Utils.toBase64(tokenStatusList.getCertificate().getEncoded())));
            }

        } else {
            LOG.debug("Status list is created as per draft-ietf-oauth-revocation-list-13 definition.");
            SDJWTClaimObject statusList = new SDJWTClaimObject(SDJWTConstants.STATUS_LIST, false);
            statusList.addChild(SDJWTClaim.create(SDJWTConstants.STATUS_LIST_IDX, tokenStatusList.getIndex()));
            statusList.addChild(SDJWTClaim.create(SDJWTConstants.STATUS_LIST_URI, tokenStatusList.getUri()));
            if (tokenStatusList.getCertificate() != null) {
                statusList.addChild(SDJWTClaim.create(SDJWTConstants.STATUS_LIST_CERTIFICATE, Utils.toBase64(tokenStatusList.getCertificate().getEncoded())));
            }
            claim.addChild(statusList);
        }

        // TODO : identifier_list ? no specification available at the moment for SD-JWT VC

        return claim;
    }

    /**
     * Builds a "cnf" claim a per RFC 7800 "Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)"
     *
     * @param payloadParameters the payload parameters
     * @return the claim or null
     */
    protected SDJWTClaim buildDeviceKeyClaim(SDJWTPayloadParameters payloadParameters) {
        if (payloadParameters.getDeviceKey() == null && payloadParameters.getDeviceKeyType() == null &&
                Utils.isCollectionEmpty(payloadParameters.getDeviceX509CertificateChain()) &&
                payloadParameters.getDeviceX509CertificateThumbprint() == null &&
                payloadParameters.getDeviceX509CertificateUrl() == null) {
            return null;
        }

        PublicKeyInfo devicePublicKeyInfo = null;
        if (payloadParameters.getDeviceKey() != null) {
            Objects.requireNonNull(publicKeyInfoFactory,
                    "PublicKeyInfoFactory shall be defined for device public key incorporation!");
            devicePublicKeyInfo = publicKeyInfoFactory.create(payloadParameters.getDeviceKey());
        }

        SDJWTClaimObject claim = new SDJWTClaimObject(SDJWTConstants.CNF, false);
        SDJWTClaim jwk = new JWKClaimBuilder()
                .publicKeyInfo(devicePublicKeyInfo)
                .keyType(payloadParameters.getDeviceKeyType())
                .certificateChain(payloadParameters.getDeviceX509CertificateChain())
                .certificateThumbprint(payloadParameters.getDeviceX509CertificateThumbprint())
                .x5u(payloadParameters.getDeviceX509CertificateUrl())
                .create();
        claim.addChild(jwk);

        return claim;
    }

    /**
     * Builds the verifiable credentials type claim.
     *
     * @param parameters the claim parameters
     * @return the claim or null
     */
    protected SDJWTClaim buildVerifiableCredentialsTypeClaim(final SDJWTPayloadParameters parameters) {
        if (parameters.getVerifiableCredentialsType() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.VERIFIABLE_CREDENTIALS_TYPE, parameters.getVerifiableCredentialsType(), false);
    }

    /**
     * Builds the verifiable credentials integrity claim.
     *
     * @param parameters the claim parameters
     * @return the claim or null
     */
    protected SDJWTClaim buildVerifiableCredentialsIntegrityClaim(final SDJWTPayloadParameters parameters) {
        if (parameters.getVerifiableCredentialsTypeIntegrity() == null) {
            return null;
        }

        Digest vctDigest = parameters.getVerifiableCredentialsTypeIntegrity();
        if (vctDigest.getAlgorithm() == null || vctDigest.getAlgorithm().getSubresourceIntegrityId() == null) {
            throw new UnsupportedOperationException(String.format(
                    "The digest algorithm '%s' is not supported for the vct#integrity claim!", vctDigest.getAlgorithm()));
        }

        String vctIntegrity = String.format("%s-%s", vctDigest.getAlgorithm().getSubresourceIntegrityId(), vctDigest.getBase64Value());
        return buildClaim(SDJWTConstants.VERIFIABLE_CREDENTIALS_INTEGRITY, vctIntegrity, false);
    }

    /**
     * Builds the issued at claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildIssuedAtClaim(final SDJWTClaimParameters parameters,
                                            final boolean selectivelyDisclosable) {
        if (parameters.getIssuanceDate() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.ISSUED_AT,
                DSSUtils.getTimeValueInSeconds(parameters.getIssuanceDate().getTime()), selectivelyDisclosable);
    }

    /**
     * Builds the subject claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildSubjectClaim(final SDJWTClaimParameters parameters,
                                           final boolean selectivelyDisclosable) {
        if (parameters.getSubject() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.SUBJECT, parameters.getSubject(), selectivelyDisclosable);
    }

    /**
     * Builds the family name claim.
     *
     * @param parameters the parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildFamilyNameClaim(final SDJWTClaimParameters parameters,
                                              final boolean selectivelyDisclosable) {
        if (parameters.getFamilyName() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_FAMILY_NAME, parameters.getFamilyName(), selectivelyDisclosable);
    }

    /**
     * Builds the given name claim.
     *
     * @param parameters the parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildGivenNameClaim(final SDJWTClaimParameters parameters,
                                             final boolean selectivelyDisclosable) {
        if (parameters.getGivenName() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_GIVEN_NAME, parameters.getGivenName(), selectivelyDisclosable);
    }

    /**
     * Builds the birth date claim.
     *
     * @param parameters the parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildBirthDateClaim(final SDJWTClaimParameters parameters,
                                             final boolean selectivelyDisclosable) {
        if (parameters.getBirthdate() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_BIRTHDATE,
                DSSUtils.formatDateToISO8601(parameters.getBirthdate()), selectivelyDisclosable);
    }

    /**
     * Builds the nationalities claim.
     *
     * @param parameters the parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaimArray buildNationalitiesClaim(final SDJWTClaimParameters parameters,
                                                      final boolean selectivelyDisclosable) {
        if (parameters.getNationalities() == null) {
            return null;
        }
        SDJWTClaimArray claim = new SDJWTClaimArray(
                SDJWTConstants.USER_NATIONALITIES, selectivelyDisclosable, null);
        parameters.getNationalities().forEach(
                nationality -> claim.addElement(SDJWTClaim.create(nationality)));
        return claim;
    }

    /**
     * Builds the address claim.
     *
     * @param parameters the parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaimObject buildAddressClaim(final SDJWTClaimParameters parameters,
                                                 final boolean selectivelyDisclosable) {
        if (Utils.areAllStringsEmpty(
                parameters.getPostalAddress(),
                parameters.getAddressStreet(),
                parameters.getAddressCity(),
                parameters.getAddressState(),
                parameters.getAddressPostalCode(),
                parameters.getAddressCountry(),
                parameters.getAddressHouseNumber())) {
            return null;
        }

        SDJWTClaimObject claim = new SDJWTClaimObject(
                SDJWTConstants.USER_ADDRESS, selectivelyDisclosable);

        if (Utils.isStringNotBlank(parameters.getPostalAddress())) {
            claim.addChild(SDJWTClaim.create(SDJWTConstants.USER_ADDRESS_FORMATTED, parameters.getPostalAddress()));
        }
        if (Utils.isStringNotBlank(parameters.getAddressStreet())) {
            claim.addChild(SDJWTClaim.create(SDJWTConstants.USER_ADDRESS_STREET_ADDRESS, parameters.getAddressStreet()));
        }
        if (Utils.isStringNotBlank(parameters.getAddressCity())) {
            claim.addChild(SDJWTClaim.create(SDJWTConstants.USER_ADDRESS_LOCALITY, parameters.getAddressCity()));
        }
        if (Utils.isStringNotBlank(parameters.getAddressState())) {
            claim.addChild(SDJWTClaim.create(SDJWTConstants.USER_ADDRESS_REGION, parameters.getAddressState()));
        }
        if (Utils.isStringNotBlank(parameters.getAddressPostalCode())) {
            claim.addChild(SDJWTClaim.create(SDJWTConstants.USER_ADDRESS_POSTAL_CODE, parameters.getAddressPostalCode()));
        }
        if (Utils.isStringNotBlank(parameters.getAddressCountry())) {
            claim.addChild(SDJWTClaim.create(SDJWTConstants.USER_ADDRESS_COUNTRY, parameters.getAddressCountry()));
        }
        if (Utils.isStringNotBlank(parameters.getAddressHouseNumber())) {
            claim.addChild(SDJWTClaim.create(SDJWTConstants.USER_ADDRESS_HOUSE_NUMBER, parameters.getAddressHouseNumber()));
        }
        return claim;
    }/**
     * Builds the email claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildEmailClaim(final SDJWTClaimParameters parameters,
                                         final boolean selectivelyDisclosable) {
        if (parameters.getEmail() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_EMAIL, parameters.getEmail(), selectivelyDisclosable);
    }

    /**
     * Builds the phone number claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildPhoneNumberClaim(final SDJWTClaimParameters parameters,
                                               final boolean selectivelyDisclosable) {
        if (parameters.getPhoneNumber() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_PHONE_NUMBER, parameters.getPhoneNumber(), selectivelyDisclosable);
    }

    /**
     * Builds the picture claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildPictureClaim(final SDJWTClaimParameters parameters,
                                           final boolean selectivelyDisclosable) {
        if (parameters.getPicture() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_PICTURE, parameters.getPicture(), selectivelyDisclosable);
    }

    /**
     * Builds the nickname claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildNicknameClaim(final SDJWTClaimParameters parameters,
                                            final boolean selectivelyDisclosable) {
        if (parameters.getNickname() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_NICKNAME, parameters.getNickname(), selectivelyDisclosable);
    }

    /**
     * Builds the preferred nickname claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildPreferredNicknameClaim(final SDJWTClaimParameters parameters,
                                                     final boolean selectivelyDisclosable) {
        if (parameters.getPreferredNickname() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_PREFERRED_NICKNAME,
                parameters.getPreferredNickname(), selectivelyDisclosable);
    }

    /**
     * Builds the name claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildNameClaim(final SDJWTClaimParameters parameters,
                                        final boolean selectivelyDisclosable) {
        if (parameters.getName() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_NAME, parameters.getName(), selectivelyDisclosable);
    }

    /**
     * Builds the middle name claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildMiddleNameClaim(final SDJWTClaimParameters parameters,
                                              final boolean selectivelyDisclosable) {
        if (parameters.getMiddleName() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_MIDDLE_NAME,
                parameters.getMiddleName(), selectivelyDisclosable);
    }

    /**
     * Builds the profile claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildProfileClaim(final SDJWTClaimParameters parameters,
                                           final boolean selectivelyDisclosable) {
        if (parameters.getProfile() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_PROFILE, parameters.getProfile(), selectivelyDisclosable);
    }

    /**
     * Builds the website claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildWebsiteClaim(final SDJWTClaimParameters parameters,
                                           final boolean selectivelyDisclosable) {
        if (parameters.getWebsite() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_WEBSITE, parameters.getWebsite(), selectivelyDisclosable);
    }

    /**
     * Builds the email verified claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildEmailVerifiedClaim(final SDJWTClaimParameters parameters,
                                                 final boolean selectivelyDisclosable) {
        if (parameters.getEmailVerified() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_EMAIL_VERIFIED,
                parameters.getEmailVerified(), selectivelyDisclosable);
    }

    /**
     * Builds the gender claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildGenderClaim(final SDJWTClaimParameters parameters,
                                          final boolean selectivelyDisclosable) {
        if (parameters.getGender() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_GENDER, parameters.getGender(), selectivelyDisclosable);
    }

    /**
     * Builds the zoneinfo claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildZoneinfoClaim(final SDJWTClaimParameters parameters,
                                            final boolean selectivelyDisclosable) {
        if (parameters.getZoneinfo() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_ZONEINFO, parameters.getZoneinfo(), selectivelyDisclosable);
    }

    /**
     * Builds the locale claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildLocaleClaim(final SDJWTClaimParameters parameters,
                                          final boolean selectivelyDisclosable) {
        if (parameters.getLocale() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_LOCALE, parameters.getLocale(), selectivelyDisclosable);
    }

    /**
     * Builds the phone number verified claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildPhoneNumberVerifiedClaim(final SDJWTClaimParameters parameters,
                                                       final boolean selectivelyDisclosable) {
        if (parameters.getPhoneNumberVerified() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_PHONE_NUMBER_VERIFIED,
                parameters.getPhoneNumberVerified(), selectivelyDisclosable);
    }

    /**
     * Builds the updated at claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildUpdatedAtClaim(final SDJWTClaimParameters parameters,
                                             final boolean selectivelyDisclosable) {
        if (parameters.getUpdatedAt() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.UPDATED_AT,
                DSSUtils.getTimeValueInSeconds(parameters.getUpdatedAt().getTime()),
                selectivelyDisclosable);
    }

    /**
     * Builds the place of birth claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaimObject buildPlaceOfBirthClaim(final SDJWTClaimParameters parameters,
                                                      final boolean selectivelyDisclosable) {
        if (Utils.areAllStringsEmpty(
                parameters.getPlaceOfBirthCountry(),
                parameters.getPlaceOfBirthRegion(),
                parameters.getPlaceOfBirthLocality())) {
            return null;
        }

        SDJWTClaimObject claim = new SDJWTClaimObject(
                SDJWTConstants.USER_PLACE_OF_BIRTH, selectivelyDisclosable);

        if (Utils.isStringNotBlank(parameters.getPlaceOfBirthCountry())) {
            claim.addChild(SDJWTClaim.create(
                    SDJWTConstants.USER_PLACE_OF_BIRTH_COUNTRY,
                    parameters.getPlaceOfBirthCountry()));
        }
        if (Utils.isStringNotBlank(parameters.getPlaceOfBirthRegion())) {
            claim.addChild(SDJWTClaim.create(
                    SDJWTConstants.USER_PLACE_OF_BIRTH_REGION,
                    parameters.getPlaceOfBirthRegion()));
        }
        if (Utils.isStringNotBlank(parameters.getPlaceOfBirthLocality())) {
            claim.addChild(SDJWTClaim.create(
                    SDJWTConstants.USER_PLACE_OF_BIRTH_LOCALITY,
                    parameters.getPlaceOfBirthLocality()));
        }
        return claim;
    }

    /**
     * Builds the birth family name claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildBirthFamilyNameClaim(final SDJWTClaimParameters parameters,
                                                   final boolean selectivelyDisclosable) {
        if (parameters.getBirthFamilyName() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_BIRTH_FAMILY_NAME,
                parameters.getBirthFamilyName(), selectivelyDisclosable);
    }

    /**
     * Builds the birth given name claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildBirthGivenNameClaim(final SDJWTClaimParameters parameters,
                                                  final boolean selectivelyDisclosable) {
        if (parameters.getBirthGivenName() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_BIRTH_GIVEN_NAME,
                parameters.getBirthGivenName(), selectivelyDisclosable);
    }

    /**
     * Builds the birth middle name claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildBirthMiddleNameClaim(final SDJWTClaimParameters parameters,
                                                   final boolean selectivelyDisclosable) {
        if (parameters.getBirthMiddleName() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_BIRTH_MIDDLE_NAME,
                parameters.getBirthMiddleName(), selectivelyDisclosable);
    }

    /**
     * Builds the salutation claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildSalutationClaim(final SDJWTClaimParameters parameters,
                                              final boolean selectivelyDisclosable) {
        if (parameters.getSalutation() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_SALUTATION,
                parameters.getSalutation(), selectivelyDisclosable);
    }

    /**
     * Builds the title claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildTitleClaim(final SDJWTClaimParameters parameters,
                                         final boolean selectivelyDisclosable) {
        if (parameters.getTitle() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_TITLE,
                parameters.getTitle(), selectivelyDisclosable);
    }

    /**
     * Builds the mobile phone number claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildMobilePhoneNumberClaim(final SDJWTClaimParameters parameters,
                                                     final boolean selectivelyDisclosable) {
        if (parameters.getMobilePhoneNumber() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_MOBILE_PHONE_NUMBER,
                parameters.getMobilePhoneNumber(), selectivelyDisclosable);
    }

    /**
     * Builds the pseudonym claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildPseudonymClaim(final SDJWTClaimParameters parameters,
                                             final boolean selectivelyDisclosable) {
        if (parameters.getPseudonym() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.USER_PSEUDONYM,
                parameters.getPseudonym(), selectivelyDisclosable);
    }

    /**
     * Builds the administrative validity not before claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildAdministrativeValidityNotBeforeClaim(final SDJWTClaimParameters parameters,
                                                                   final boolean selectivelyDisclosable) {
        if (parameters.getAdministrativeIssuanceDate() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.ADMINISTRATIVE_VALIDITY_NOT_BEFORE,
                DSSUtils.getTimeValueInSeconds(parameters.getAdministrativeIssuanceDate().getTime()), selectivelyDisclosable);
    }

    /**
     * Builds the administrative validity expiry claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildAdministrativeValidityExpiryClaim(final SDJWTClaimParameters parameters,
                                                                final boolean selectivelyDisclosable) {
        if (parameters.getAdministrativeExpirationDate() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.ADMINISTRATIVE_VALIDITY_EXPIRY,
                DSSUtils.getTimeValueInSeconds(parameters.getAdministrativeExpirationDate().getTime()), selectivelyDisclosable);
    }

    /**
     * Builds the date of expiry claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildDateOfExpiryClaim(final SDJWTClaimParameters parameters,
                                                final boolean selectivelyDisclosable) {
        if (parameters.getDateOfExpiry() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.EXPIRY_DATE,
                DSSUtils.formatDateToISO8601(parameters.getDateOfExpiry()),
                selectivelyDisclosable);
    }

    /**
     * Builds the date of issuance claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildDateOfIssuanceClaim(final SDJWTClaimParameters parameters,
                                                  final boolean selectivelyDisclosable) {
        if (parameters.getDateOfIssuance() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.ISSUANCE_DATE,
                DSSUtils.formatDateToISO8601(parameters.getDateOfIssuance()),
                selectivelyDisclosable);
    }/**
     * Builds the personal administrative number claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildPersonalAdministrativeNumberClaim(final SDJWTClaimParameters parameters,
                                                                final boolean selectivelyDisclosable) {
        if (parameters.getPersonalAdministrativeNumber() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.PERSONAL_ADMINISTRATIVE_NUMBER,
                parameters.getPersonalAdministrativeNumber(), selectivelyDisclosable);
    }

    /**
     * Builds the sex claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildSexClaim(final SDJWTClaimParameters parameters,
                                       final boolean selectivelyDisclosable) {
        if (parameters.getSex() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.SEX,
                parameters.getSex(), selectivelyDisclosable);
    }

    /**
     * Builds the issuing authority claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildIssuingAuthorityClaim(final SDJWTClaimParameters parameters,
                                                    final boolean selectivelyDisclosable) {
        if (parameters.getIssuingAuthority() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.ISSUING_AUTHORITY,
                parameters.getIssuingAuthority(), selectivelyDisclosable);
    }

    /**
     * Builds the issuing country claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildIssuingCountryClaim(final SDJWTClaimParameters parameters,
                                                  final boolean selectivelyDisclosable) {
        if (parameters.getIssuingCountry() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.ISSUING_COUNTRY,
                parameters.getIssuingCountry(), selectivelyDisclosable);
    }

    /**
     * Builds the document number claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildDocumentNumberClaim(final SDJWTClaimParameters parameters,
                                                  final boolean selectivelyDisclosable) {
        if (parameters.getDocumentNumber() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.DOCUMENT_NUMBER,
                parameters.getDocumentNumber(), selectivelyDisclosable);
    }

    /**
     * Builds the issuing jurisdiction claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildIssuingJurisdictionClaim(final SDJWTClaimParameters parameters,
                                                       final boolean selectivelyDisclosable) {
        if (parameters.getIssuingJurisdiction() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.ISSUING_JURISDICTION,
                parameters.getIssuingJurisdiction(), selectivelyDisclosable);
    }

    /**
     * Builds the age in years claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildAgeInYearsClaim(final SDJWTClaimParameters parameters,
                                              final boolean selectivelyDisclosable) {
        if (parameters.getAgeInYears() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.AGE_IN_YEARS,
                parameters.getAgeInYears(), selectivelyDisclosable);
    }

    /**
     * Builds the age birth year claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildAgeBirthYearClaim(final SDJWTClaimParameters parameters,
                                                final boolean selectivelyDisclosable) {
        if (parameters.getAgeBirthYear() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.AGE_BIRTH_YEAR,
                parameters.getAgeBirthYear(), selectivelyDisclosable);
    }

    /**
     * Builds the trust anchor claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildTrustAnchorClaim(final SDJWTClaimParameters parameters,
                                               final boolean selectivelyDisclosable) {
        if (parameters.getTrustAnchor() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.TRUST_ANCHOR,
                parameters.getTrustAnchor(), selectivelyDisclosable);
    }

    /**
     * Builds the age equal or over claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaimObject buildAgeEqualOrOverClaim(final SDJWTClaimParameters parameters,
                                                        final boolean selectivelyDisclosable) {
        if (parameters.getAgeOverNN() == null) {
            return null;
        }

        SDJWTClaimObject claim = new SDJWTClaimObject(
                SDJWTConstants.AGE_EQUAL_OR_OVER, selectivelyDisclosable);

        parameters.getAgeOverNN().forEach((age, verified) -> {
            if (age != null && verified != null) {
                claim.addChild(SDJWTClaim.create(Integer.toString(age), verified));
            }
        });

        return claim;
    }

    /**
     * Builds the issuing registration identifier claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildIssuingRegistrationIdentifierClaim(final SDJWTClaimParameters parameters,
                                                                 final boolean selectivelyDisclosable) {
        if (parameters.getIssuingAuthorityRegistrationIdentifier() == null) {
            return null;
        }
        return buildClaim(SDJWTConstants.ISSUING_REGISTRATION_IDENTIFIER,
                parameters.getIssuingAuthorityRegistrationIdentifier(), selectivelyDisclosable);
    }

    /**
     * Builds the attested attribute subject claim.
     *
     * @param parameters the claim parameters
     * @param selectivelyDisclosable whether selectively disclosable
     * @return the claim or null
     */
    protected SDJWTClaim buildAttestedAttributesSubject(SDJWTClaimParameters parameters, boolean selectivelyDisclosable) {
        if (Utils.areAllStringsEmpty(parameters.getAttestedAttributesSubjectIdentifier(),
                parameters.getAttestedAttributesSubjectPseudonym()) && Utils.isCollectionEmpty(parameters.getAttestedAttributes())) {
            return null;
        }

        if ((parameters.getAttestedAttributesSubjectIdentifier() == null) == (parameters.getAttestedAttributesSubjectPseudonym() == null)) {
            throw new IllegalArgumentException("Either attested attributes subject identifier or " +
                    "attested attributes subject pseudonym shall be present!");
        }

        SDJWTClaimObject claim = new SDJWTClaimObject(SDJWTConstants.ATTESTED_ATTRIBUTES_SUBJECT, selectivelyDisclosable);
        if (Utils.isStringNotBlank(parameters.getAttestedAttributesSubjectIdentifier())) {
            claim.addChild(SDJWTClaim.create(
                    SDJWTConstants.ATTESTED_ATTRIBUTES_SUBJECT_ID,
                    parameters.getAttestedAttributesSubjectIdentifier()));
        }
        if (Utils.isStringNotBlank(parameters.getAttestedAttributesSubjectPseudonym())) {
            claim.addChild(SDJWTClaim.create(
                    SDJWTConstants.ATTESTED_ATTRIBUTES_SUBJECT_AKA,
                    parameters.getAttestedAttributesSubjectPseudonym()));
        }
        if (Utils.isCollectionNotEmpty(parameters.getAttestedAttributes())) {
            claim.addChild(SDJWTClaim.create(
                    SDJWTConstants.ATTESTED_ATTRIBUTES_SUBJECT_ATTRIBUTES,
                    parameters.getAttestedAttributes()));
        }
        return claim;
    }

    /**
     * Builds a claim for the given configuration
     *
     * @param name {@link String}
     * @param value {@link Object}
     * @param selectivelyDisclosable whether the claim is to be made selectively disclosable
     * @return {@link SDJWTClaim}
     */
    protected SDJWTClaim buildClaim(final String name, final Object value, final boolean selectivelyDisclosable) {
        return selectivelyDisclosable ? SDJWTClaim.createSelectivelyDisclosable(name, value) : SDJWTClaim.create(name, value);
    }

    /**
     * Utility method to add a claim if not null
     *
     * @param claims a list of {@link SDJWTClaim}s to be populated
     * @param claim {@link SDJWTClaim} to add if not null
     */
    protected void addIfNotNull(final List<SDJWTClaim> claims, final SDJWTClaim claim) {
        if (claim != null) {
            claims.add(claim);
        }
    }

}
