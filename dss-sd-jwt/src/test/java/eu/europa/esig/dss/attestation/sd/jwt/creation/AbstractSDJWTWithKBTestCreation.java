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
import eu.europa.esig.dss.attestation.common.validation.AbstractAttestationPresentationTestCreation;
import eu.europa.esig.dss.attestation.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.AttestationDocumentFormat;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractSDJWTWithKBTestCreation extends AbstractAttestationPresentationTestCreation<
        JAdESSignatureParameters, SDJWTPayloadParameters, SDJWTSelectiveDisclosure, SDJWTKeyBindingParameters> {

    @Override
    protected SDJWTService getService() {
        return new SDJWTService(getOfflineCertificateVerifier());
    }

    @Override
    protected SDJWTService getPresentationService() {
        return new SDJWTService(getOfflineCertificateVerifier());
    }

    @Override
    protected MimeType getExpectedMime() {
        return MimeTypeEnum.JSON;
    }

    @Override
    protected AttestationProfile getAttestationType() {
        return AttestationProfile.SD_JWT_VC;
    }

    @Override
    protected AttestationDocumentFormat getAttestationPresentationType() {
        return AttestationDocumentFormat.SD_JWT;
    }

    @Override
    protected boolean keyBindingPresent() {
        return true;
    }

    @Override
    @SuppressWarnings("unchecked")
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        for (AdvancedSignature signature : signatures) {
            assertInstanceOf(JAdESSignature.class, signature);

            JAdESSignature jadesSignature = (JAdESSignature) signature;
            if (signature.isKeyBindingSignature()) {
                assertEquals(MimeTypeEnum.KB_JWT.getMimeTypeString(), jadesSignature.getSignatureType());
            } else {
                assertEquals(MimeTypeEnum.SD_JWT_VC.getMimeTypeString(), jadesSignature.getSignatureType());
            }

            JWS jws = jadesSignature.getJws();

            List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
            assertTrue(Utils.isCollectionEmpty(etsiU));

            Headers headers = jws.getHeaders();
            Set<String> keySet = DSSJsonUtils.extractJOSEHeaderMembersSet(jws);
            assertTrue(Utils.isCollectionNotEmpty(keySet));
            for (String signedPropertyName : keySet) {
                assertTrue(DSSJsonUtils.getSupportedProtectedCriticalHeaders().contains(signedPropertyName) ||
                        DSSJsonUtils.isCriticalHeaderException(signedPropertyName) ||
                        JAdESHeaderParameterNames.ETSI_U.equals(signedPropertyName) ||
                        SDJWTConstants.DISCLOSURES.equals(signedPropertyName) ||
                        SDJWTConstants.KB_JWT.equals(signedPropertyName));
            }

            Object crit = headers.getObjectHeaderValue(HeaderParameterNames.CRITICAL);
            if (crit != null) {
                assertInstanceOf(List.class, crit);

                List<String> critArray = (List<String>) crit;
                assertTrue(Utils.isCollectionNotEmpty(critArray));
                for (String critItem : critArray) {
                    assertTrue(DSSJsonUtils.getSupportedProtectedCriticalHeaders().contains(critItem));
                    assertTrue(DSSJsonUtils.isRequiredCriticalHeader(critItem));
                    assertFalse(DSSJsonUtils.isCriticalHeaderException(critItem));
                }
            }
        }
    }

    @Override
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        super.checkAttestationDigestMatchers(diagnosticData);

        for (AttestationWrapper attestation : diagnosticData.getAttestations()) {
            for (XmlDigestMatcher xmlDigestMatcher : attestation.getDigestMatchers()) {
                if (DigestMatcherType.SELECTIVE_DISCLOSURE == xmlDigestMatcher.getType()) {
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim());
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim().getValue());
                    assertNull(xmlDigestMatcher.getDisclosableClaim().getNamespace());
                    assertNull(xmlDigestMatcher.getDisclosableClaim().getId());
                }
            }
        }
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        for (AttestationWrapper attestation : diagnosticData.getAttestations()) {

            assertNotNull(attestation.getNotBefore());
            assertNotNull(attestation.getExpiration());

            assertEquals(getPayloadParameters().getIssuer(), attestation.getIssuer());
            // TODO : deviceKeyType
            // assertEquals(getPayloadParameters().getDeviceKeyType(), attestation.getDeviceKeyType());

            if (getPayloadParameters().getDeviceKey() != null) {
                assertArrayEquals(getPayloadParameters().getDeviceKey().getEncoded(), attestation.getDevicePublicKey());
            } else {
                assertNull(attestation.getDevicePublicKey());
            }

            // TODO : not yet supported
            assertEquals(0, Utils.collectionSize(attestation.getDeviceCertificateKIDs()));

            assertEquals(getPayloadParameters().getVerifiableCredentialsType(), attestation.getVerifiableCredentialsTypeUri());

            if (getPayloadParameters().getVerifiableCredentialsTypeIntegrity() != null) {
                assertEquals(getPayloadParameters().getVerifiableCredentialsTypeIntegrity().getAlgorithm(), attestation.getVerifiableCredentialsTypeIntegrityDigestAlgorithm());
                assertArrayEquals(getPayloadParameters().getVerifiableCredentialsTypeIntegrity().getValue(), attestation.getVerifiableCredentialsTypeIntegrityBytes());
            } else {
                assertNull(attestation.getVerifiableCredentialsTypeIntegrityDigestAlgorithm());
                assertNull(attestation.getVerifiableCredentialsTypeIntegrityBytes());
            }

            assertEquals(getPayloadParameters().getDigestAlgorithm(), attestation.getSelectiveDisclosuresDigestAlgorithm());

            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getNotBeforeDate()), DSSUtils.formatDateToRFC(attestation.getNotBefore()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getExpirationDate()), DSSUtils.formatDateToRFC(attestation.getExpiration()));

            assertStatusListEqual(getPayloadParameters().getStatusList(), attestation);

            assertEquals(getPayloadParameters().getCategory(), attestation.getCategory());
            assertEquals(Utils.isTrue(getPayloadParameters().isShortLived()), Utils.isTrue(attestation.getShortLived()));
            assertEquals(Utils.isTrue(getPayloadParameters().isOneTime()), Utils.isTrue(attestation.getOneTimeUse()));

            assertSDJWTClaims(getPayloadParameters().selectivelyDisclosable(), getPayloadParameters().nonSelectivelyDisclosable(), attestation);
        }
    }

    protected void assertStatusListEqual(TokenStatusList statusList, AttestationWrapper attestation) {
        if (statusList != null) {
            if (statusList instanceof ETSITokenStatusList) {
                ETSITokenStatusList etsiTokenStatusList = (ETSITokenStatusList) statusList;
                assertEquals(etsiTokenStatusList.getType(), attestation.getStatusType());
                assertEquals(etsiTokenStatusList.getPurpose(), attestation.getStatusPurpose());
            } else {
                assertNull(attestation.getStatusType());
                assertNull(attestation.getStatusPurpose());
            }
            assertEquals(statusList.getIndex(), attestation.getStatusIndex());
            assertEquals(statusList.getUri(), attestation.getStatusUri());
            if (statusList.getCertificate() != null) {
                assertArrayEquals(statusList.getCertificate().getEncoded(), attestation.getStatusCertificate());
            } else {
                assertNull(attestation.getStatusCertificate());
            }
        } else {
            assertNull(attestation.getStatusIndex());
            assertNull(attestation.getStatusUri());
            assertNull(attestation.getStatusCertificate());
        }
    }

    protected void assertSDJWTClaims(SDJWTClaimParameters sd, SDJWTClaimParameters nonSd, AttestationWrapper attestation) {

        assertEitherDate(sd.getIssuanceDate(), nonSd.getIssuanceDate(), attestation.getIssuedAt());
        assertEither(sd.getSubject(), nonSd.getSubject(), attestation.getSubject());

        assertEither(sd.getGivenName(), nonSd.getGivenName(), attestation.getGivenName());
        assertEither(sd.getFamilyName(), nonSd.getFamilyName(), attestation.getFamilyName());
        assertEither(sd.getEmail(), nonSd.getEmail(), attestation.getEmail());
        assertEither(sd.getPhoneNumber(), nonSd.getPhoneNumber(), attestation.getPhoneNumber());
        assertEither(sd.getPhoneNumberVerified(), nonSd.getPhoneNumberVerified(), attestation.getPhoneNumberVerified());
        assertEitherDate(sd.getBirthdate(), nonSd.getBirthdate(), attestation.getBirthdate());

        assertEither(sd.getNationalities(), nonSd.getNationalities(), attestation.getNationalities());

        assertEither(sd.getPostalAddress(), nonSd.getPostalAddress(), attestation.getResidentPostalAddress());
        assertEither(sd.getAddressHouseNumber(), nonSd.getAddressHouseNumber(), attestation.getResidentAddressHouseNumber());
        assertEither(sd.getAddressStreet(), nonSd.getAddressStreet(), attestation.getResidentAddressStreet());
        assertEither(sd.getAddressCity(), nonSd.getAddressCity(), attestation.getResidentAddressCity());
        assertEither(sd.getAddressState(), nonSd.getAddressState(), attestation.getResidentAddressState());
        assertEither(sd.getAddressPostalCode(), nonSd.getAddressPostalCode(), attestation.getResidentAddressPostalCode());
        assertEither(sd.getAddressCountry(), nonSd.getAddressCountry(), attestation.getResidentAddressCountry());

        assertEither(sd.getPlaceOfBirthCountry(), nonSd.getPlaceOfBirthCountry(), attestation.getPlaceOfBirth());
        assertEither(sd.getPlaceOfBirthRegion(), nonSd.getPlaceOfBirthRegion(), attestation.getPlaceOfBirthRegion());
        assertEither(sd.getPlaceOfBirthLocality(), nonSd.getPlaceOfBirthLocality(), attestation.getPlaceOfBirthCity());

        assertEither(sd.getBirthGivenName(), nonSd.getBirthGivenName(), attestation.getBirthGivenName());
        assertEither(sd.getBirthFamilyName(), nonSd.getBirthFamilyName(), attestation.getBirthFamilyName());
        assertEither(sd.getTitle(), nonSd.getTitle(), attestation.getTitle());
        assertEither(sd.getMobilePhoneNumber(), nonSd.getMobilePhoneNumber(), attestation.getMobilePhoneNumber());
        assertEither(sd.getPseudonym(), nonSd.getPseudonym(), attestation.getPseudonym());

        assertEither(sd.getPersonalAdministrativeNumber(), nonSd.getPersonalAdministrativeNumber(), attestation.getPersonalAdministrativeNumber());

        if (sd.getSex() != null || nonSd.getSex() != null) {
            assertEither(sd.getSex(), nonSd.getSex(), attestation.getGender());
        } else {
            assertEither(sd.getGender(), nonSd.getGender(), attestation.getGender());
        }

        assertEither(sd.getIssuingCountry(), nonSd.getIssuingCountry(), attestation.getDocumentIssuingAuthorityCountry());
        assertEither(sd.getIssuingAuthority(), nonSd.getIssuingAuthority(), attestation.getDocumentIssuingAuthority());
        assertEither(sd.getIssuingJurisdiction(), nonSd.getIssuingJurisdiction(), attestation.getDocumentIssuingAuthorityJurisdiction());
        assertEither(sd.getDocumentNumber(), nonSd.getDocumentNumber(), attestation.getDocumentNumber());

        assertEither(sd.getAgeInYears(), nonSd.getAgeInYears(), attestation.getAgeInYears());
        assertEither(sd.getAgeBirthYear(), nonSd.getAgeBirthYear(), attestation.getAgeBirthYear());
        assertEither(sd.getTrustAnchor(), nonSd.getTrustAnchor(), attestation.getTrustAnchor());

        if (Utils.isMapNotEmpty(sd.getAgeOverNN()) || Utils.isMapNotEmpty(nonSd.getAgeOverNN())) {
            Set<Integer> ages = new HashSet<>();

            if (Utils.isMapNotEmpty(sd.getAgeOverNN())) {
                ages.addAll(sd.getAgeOverNN().keySet());
            }

            if (Utils.isMapNotEmpty(nonSd.getAgeOverNN())) {
                ages.addAll(nonSd.getAgeOverNN().keySet());
            }

            for (Integer age : ages) {
                Boolean sdValue = Utils.isMapNotEmpty(sd.getAgeOverNN()) ? sd.getAgeOverNN().get(age) : null;
                Boolean nonSdValue = Utils.isMapNotEmpty(nonSd.getAgeOverNN()) ? nonSd.getAgeOverNN().get(age) : null;

                assertEither(sdValue, nonSdValue, attestation.isAgeOver(age));
            }
        }

        assertEither(sd.getIssuingAuthorityRegistrationIdentifier(), nonSd.getIssuingAuthorityRegistrationIdentifier(), attestation.getIssuingRegistrationIdentifier());

        if (sd.getDateOfIssuance() != null || nonSd.getDateOfIssuance() != null) {
            assertEitherDate(sd.getDateOfIssuance(), nonSd.getDateOfIssuance(), attestation.getAdministrativeIssuanceDate());
        } else {
            assertEitherDate(sd.getAdministrativeIssuanceDate(), nonSd.getAdministrativeIssuanceDate(), attestation.getAdministrativeIssuanceDate());
        }
        if (sd.getDateOfExpiry() != null || nonSd.getDateOfExpiry() != null) {
            assertEitherDate(sd.getDateOfExpiry(), nonSd.getDateOfExpiry(), attestation.getAdministrativeExpirationDate());
        } else {
            assertEitherDate(sd.getAdministrativeExpirationDate(), nonSd.getAdministrativeExpirationDate(), attestation.getAdministrativeExpirationDate());
        }

        assertEither(sd.getPicture(), nonSd.getPicture(), attestation.getPictureUrl());
        assertEither(sd.getNickname(), nonSd.getNickname(), attestation.getNickname());

        assertEither(sd.getPreferredNickname(), nonSd.getPreferredNickname(), attestation.getShortName());

        assertEither(sd.getName(), nonSd.getName(), attestation.getFullName());
        assertEither(sd.getMiddleName(), nonSd.getMiddleName(), attestation.getMiddleName());
        assertEither(sd.getProfile(), nonSd.getProfile(), attestation.getProfileUrl());
        assertEither(sd.getWebsite(), nonSd.getWebsite(), attestation.getWebsiteUrl());

        assertEither(sd.getEmailVerified(), nonSd.getEmailVerified(), attestation.getEmailVerified());

        assertEither(sd.getZoneinfo(), nonSd.getZoneinfo(), attestation.getTimezone());
        assertEither(sd.getLocale(), nonSd.getLocale(), attestation.getLocale());
        assertEither(sd.getPhoneNumberVerified(), nonSd.getPhoneNumberVerified(), attestation.getPhoneNumberVerified());

        assertEitherDate(sd.getUpdatedAt(), nonSd.getUpdatedAt(), attestation.getUpdatedAt());

        assertEither(sd.getBirthMiddleName(), nonSd.getBirthMiddleName(), attestation.getBirthMiddleName());
        assertEither(sd.getSalutation(), nonSd.getSalutation(), attestation.getSalutation());

        assertEither(sd.getAttestedAttributesSubjectIdentifier(), nonSd.getAttestedAttributesSubjectIdentifier(), attestation.getAttestedAttributesSubjectId());
        assertEither(sd.getAttestedAttributesSubjectPseudonym(), nonSd.getAttestedAttributesSubjectPseudonym(), attestation.getAttestedAttributesSubjectPseudonym());

        List<ClaimWrapper> selectivelyDisclosableClaims = attestation.getSelectiveDisclosures();
        if (parametersContainSelectivelyDisclosablClaims()) {
            assertFalse(selectivelyDisclosableClaims.isEmpty());
        } else {
            assertTrue(selectivelyDisclosableClaims.isEmpty());
        }
    }

    private <T> void assertEither(T sdValue, T nonSdValue, T actual) {
        if (sdValue == null && nonSdValue == null) {
            assertNull(actual);
        } else {
            assertTrue(Objects.equals(sdValue, actual) ||  Objects.equals(nonSdValue, actual),
                    String.format("Expected [%s] or [%s] but got [%s]", sdValue, nonSdValue, actual));
        }
    }

    private void assertEitherDate(Date sdValue, Date nonSdValue, Date actual) {
        if (actual == null && sdValue == null) {
            assertNull(actual);

        } else {
            String actualValue = DSSUtils.formatDateToRFC(actual);
            String sdFormatted = DSSUtils.formatDateToRFC(sdValue);
            String nonSdFormatted = DSSUtils.formatDateToRFC(nonSdValue);

            assertTrue(Objects.equals(sdFormatted, actualValue) || Objects.equals(nonSdFormatted, actualValue),
                    String.format("Expected [%s] or [%s] but got [%s]", sdFormatted, nonSdFormatted, actualValue));
        }
    }

    private boolean parametersContainSelectivelyDisclosablClaims() {
        if (hasConfiguredClaims(getPayloadParameters().selectivelyDisclosable())) {
            return true;
        }

        return hasSDClaims(getPayloadParameters().selectivelyDisclosable()) || hasSDClaims(getPayloadParameters().nonSelectivelyDisclosable());
    }

    private boolean hasConfiguredClaims(SDJWTClaimParameters p) {
        return p.getIssuanceDate() != null
                || p.getSubject() != null

                || p.getGivenName() != null
                || p.getFamilyName() != null
                || p.getBirthdate() != null
                || (p.getNationalities() != null && !p.getNationalities().isEmpty())
                || p.getEmail() != null
                || p.getPhoneNumber() != null

                || p.getPostalAddress() != null
                || p.getAddressHouseNumber() != null
                || p.getAddressStreet() != null
                || p.getAddressCity() != null
                || p.getAddressState() != null
                || p.getAddressPostalCode() != null
                || p.getAddressCountry() != null

                || p.getPlaceOfBirthCountry() != null
                || p.getPlaceOfBirthRegion() != null
                || p.getPlaceOfBirthLocality() != null
                || p.getBirthGivenName() != null
                || p.getBirthFamilyName() != null
                || p.getTitle() != null
                || p.getMobilePhoneNumber() != null
                || p.getPseudonym() != null

                || p.getPersonalAdministrativeNumber() != null
                || p.getSex() != null
                || p.getIssuingCountry() != null
                || p.getIssuingAuthority() != null
                || p.getIssuingJurisdiction() != null
                || p.getDocumentNumber() != null
                || p.getAgeInYears() != null
                || p.getAgeBirthYear() != null
                || p.getTrustAnchor() != null
                || (p.getAgeOverNN() != null && !p.getAgeOverNN().isEmpty())

                || p.getIssuingAuthorityRegistrationIdentifier() != null
                || p.getAdministrativeIssuanceDate() != null
                || p.getAdministrativeExpirationDate() != null

                || p.getPicture() != null
                || p.getNickname() != null
                || p.getPreferredNickname() != null
                || p.getName() != null
                || p.getMiddleName() != null
                || p.getProfile() != null
                || p.getWebsite() != null
                || p.getEmailVerified() != null
                || p.getGender() != null
                || p.getZoneinfo() != null
                || p.getLocale() != null
                || p.getPhoneNumberVerified() != null
                || p.getUpdatedAt() != null

                || p.getBirthMiddleName() != null
                || p.getSalutation() != null

                || p.getDateOfExpiry() != null
                || p.getDateOfIssuance() != null

                || p.getAttestedAttributesSubjectIdentifier() != null
                || p.getAttestedAttributesSubjectPseudonym() != null
                || (p.getAttestedAttributes() != null && !p.getAttestedAttributes().isEmpty())

                || !p.getOtherClaims().isEmpty();
    }

    private boolean hasSDClaims(SDJWTClaimParameters claimParameters) {
        return claimParameters.getOtherClaims().stream().anyMatch(this::hasSDClaims);
    }

    private boolean hasSDClaims(SDJWTClaim claim) {
        if (claim == null) {
            return false;
        }

        if (claim.isSelectivelyDisclosable()) {
            return true;
        }

        if (claim instanceof SDJWTClaimObject) {
            SDJWTClaimObject object = (SDJWTClaimObject) claim;

            return object.getChildren() != null
                    && object.getChildren().stream().anyMatch(this::hasSDClaims);

        } else if (claim instanceof SDJWTClaimArray) {
            SDJWTClaimArray array = (SDJWTClaimArray) claim;

            return array.getElements() != null
                    && array.getElements().stream().anyMatch(this::hasSDClaims);

        } else {
            return false;
        }
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        super.checkSigningCertificateValue(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            JAdESSignatureParameters signatureParameters = signatureWrapper.isKeyBindingSignature() ? getKeyBindingSignatureParameters() : getSignatureParameters();
            FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
            List<RelatedCertificateWrapper> signingCertificates = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);

            // For a key binding signature where no x5c certificate chain is provided via the CNF claim, no certificate is accessible and certificate-ref checks are skipped.
            boolean checkCertificates = !signatureWrapper.isKeyBindingSignature() || !signingCertificates.isEmpty();


            if (checkCertificates) {
                assertEquals(1, signingCertificates.size());

                List<CertificateRefWrapper> references = signingCertificates.get(0).getReferences();
                List<RelatedCertificateWrapper> kidCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER);
                List<RelatedCertificateWrapper> x5uCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.X509_URL);

                int signCertRefs = 1 + (Utils.isCollectionNotEmpty(kidCerts) ? 1 : 0) + (Utils.isCollectionNotEmpty(x5uCerts) ? 1 : 0);
                assertEquals(signCertRefs, references.size());

                if (signatureParameters.isIncludeKeyIdentifier()) {
                    assertEquals(1, kidCerts.size());
                } else if (Utils.isStringNotEmpty(signatureParameters.getX509Url())) {
                    assertTrue(Utils.isCollectionNotEmpty(x5uCerts));
                } else {
                    assertEquals(0, kidCerts.size());
                    assertEquals(0, x5uCerts.size());
                }

                for (CertificateRefWrapper certificateRef : references) {
                    if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRef.getOrigin())) {
                        assertNotNull(certificateRef.getDigestAlgoAndValue());
                        assertNotNull(certificateRef.getDigestMethod());
                        assertTrue(certificateRef.isDigestValuePresent());
                        assertTrue(certificateRef.isDigestValueMatch());
                        assertNull(certificateRef.getIssuerSerial());

                    } else if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRef.getOrigin())) {
                        assertNotNull(certificateRef.getCertificateId());
                        if (certificateRef.getIssuerSerial() != null) {
                            assertNotNull(certificateRef.getIssuerSerial());
                            assertTrue(certificateRef.isIssuerSerialPresent());
                            assertTrue(certificateRef.isIssuerSerialMatch());
                        } else {
                            assertNotNull(certificateRef.getKid());
                        }
                        assertNull(certificateRef.getDigestAlgoAndValue());

                    } else if (CertificateRefOrigin.X509_URL.equals(certificateRef.getOrigin())) {
                        assertNotNull(certificateRef.getCertificateId());
                        assertNotNull(certificateRef.getX509Url());
                    }
                }
            } else {
                assertEquals(0, signingCertificates.size());
            }
        }
    }

    @Override
    protected void checkContentType(DiagnosticData diagnosticData) {
        super.checkContentType(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            // The cty header parameter should not be present if the content type is implied by the JWS Payload.
            assertNull(signatureWrapper.getContentType());
        }
    }

    @Override
    protected void validateSignerInformation(final SignerInformationType signerInformation) {
        // Skip check in case of key binding signature as we might not have the signer information if the certificate was not provided
        if (!keyBindingPresent()) {
            super.validateSignerInformation(signerInformation);
        }
    }

}
