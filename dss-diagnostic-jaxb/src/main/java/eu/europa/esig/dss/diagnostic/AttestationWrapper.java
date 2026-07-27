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
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DeviceKeyClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegesClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.IntegrityClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.PlaceOfBirthClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.StatusClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.ValidityInfoClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationRevocationStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.AttestationProfile;
import eu.europa.esig.dss.enumerations.AttestationQualification;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EAACategory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Provides a user-friendly interface for information extraction from a {@code eu.europa.esig.dss.diagnostic.jaxb.XmlAttestation} JAXB object
 *
 */
public class AttestationWrapper extends AbstractTokenProxy {

    /** Wrapped attestation object */
    private final XmlAttestation attestation;

    /**
     * Default constructor
     *
     * @param attestation {@link XmlAttestation} to read
     */
    public AttestationWrapper(final XmlAttestation attestation) {
        this.attestation = attestation;
    }

    /**
     * Gets unique identifier
     *
     * @return {@link String}
     */
    public String getId() {
        return attestation.getId();
    }

    /**
     * Returns name of the attestation presentation's document, when applicable
     *
     * @return {@link String}
     */
    public String getFilename() {
        return attestation.getDocumentName();
    }

    /**
     * Gets claimed document type.
     * NOTE: used in mdoc and the returned value corresponds to a string incorporated within a 'docType' element
     *
     * @return {@link String}
     */
    public String getAttestationDocumentType() {
        String docType = getPayloadClaimTextValue(getPayload().getDocType());
        if (docType != null) {
            return docType;
        }
        return attestation.getDocumentType();
    }

    @Override
    protected XmlBasicSignature getCurrentBasicSignature() {
        SignatureWrapper attestationSignature = getAttestationSignature();
        if (attestationSignature != null) {
            return attestationSignature.getCurrentBasicSignature();
        }
        return null;
    }

    @Override
    protected List<XmlChainItem> getCurrentCertificateChain() {
        SignatureWrapper attestationSignature = getAttestationSignature();
        if (attestationSignature != null) {
            return attestationSignature.getCurrentCertificateChain();
        }
        return null;
    }

    @Override
    protected XmlSigningCertificate getCurrentSigningCertificate() {
        SignatureWrapper attestationSignature = getAttestationSignature();
        if (attestationSignature != null) {
            return attestationSignature.getCurrentSigningCertificate();
        }
        return null;
    }

    private SignatureWrapper getAttestationSignature() {
        List<SignatureWrapper> attestationSignatures = getAttestationSignatures();
        if (attestationSignatures != null && attestationSignatures.size() == 1) {
            return attestationSignatures.get(0);
        }
        return null;
    }

    /**
     * Gets digest algorithm used on hashes computation for selectively disclosable claims
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getSelectiveDisclosuresDigestAlgorithm() {
        return attestation.getDigestMethod();
    }

    /**
     * Gets a list of digest matchers representing the associated hashes and disclosures validation
     *
     * @return a list of {@link XmlDigestMatcher}
     */
    @Override
    public List<XmlDigestMatcher> getDigestMatchers() {
        return attestation.getDigestMatchers();
    }

    /**
     * Gets signatures used to create the attestation.
     * NOTE: in most of the cases a single signature is expected,
     * but it is possible for attestation to be signed by multiple signers.
     *
     * @return a list of {@link SignatureWrapper}s
     */
    public List<SignatureWrapper> getAttestationSignatures() {
        final List<SignatureWrapper> result = new ArrayList<>();
        for (XmlAttestationSignature xmlAttestationSignature : attestation.getAttestationSignature()) {
            result.add(new SignatureWrapper(xmlAttestationSignature.getSignature()));
        }
        return result;
    }

    /**
     * Gets a list of identifiers of signatures used to create the attestation
     *
     * @return a list of {@link String}s
     */
    public List<String> getAttestationSignatureIds() {
        List<SignatureWrapper> attestationPresentationSignatures = getAttestationSignatures();
        if (attestationPresentationSignatures != null && !attestationPresentationSignatures.isEmpty()) {
            return attestationPresentationSignatures.stream().map(SignatureWrapper::getId).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    /**
     * Gets a key binding signature, when present
     *
     * @return {@link SignatureWrapper}
     */
    public SignatureWrapper getKeyBindingSignature() {
        if (attestation.getKeyBindingSignature() != null) {
            return new SignatureWrapper(attestation.getKeyBindingSignature().getSignature());
        }
        return null;
    }

    /**
     * Gets unique identifier of the key binding signature, when present
     *
     * @return {@link String}
     */
    public String getKeyBindingSignatureId() {
        SignatureWrapper keyBindingSignature = getKeyBindingSignature();
        if (keyBindingSignature != null) {
            return keyBindingSignature.getId();
        }
        return null;
    }

    /**
     * Gets access to the attestation payload, containing complete claims data
     *
     * @return {@link AttestationPayloadProxy}
     */
    public AttestationPayloadProxy getPayload() {
        return new AttestationPayloadProxy(attestation.getAttestationPayload());
    }

    /**
     * Gets the nonce provided in the key binding signature payload
     *
     * @return {@link String}
     */
    public String getKeyBindingSignatureNonce() {
        if (attestation.getKeyBindingPayload() == null) {
            return null;
        }

        final XmlClaim nonce = attestation.getKeyBindingPayload().getNonce();
        if (nonce != null) {
            return nonce.getText();
        }

        return null;
    }

    /**
     * Gets the audience provided in the key binding signature payload
     *
     * @return {@link String}
     */
    public String getKeyBindingSignatureAudience() {
        if (attestation.getKeyBindingPayload() == null) {
            return null;
        }

        final XmlClaim audience = attestation.getKeyBindingPayload().getAudience();
        if (audience != null) {
            return audience.getText();
        }

        return null;
    }

    /**
     * Gets the issuance time provided in the key binding signature payload
     *
     * @return {@link Date}
     */
    public Date getKeyBindingSignatureIssuanceTime() {
        if (attestation.getKeyBindingPayload() == null) {
            return null;
        }

        final XmlClaim issuanceTime = attestation.getKeyBindingPayload().getIssuanceTime();
        if (issuanceTime != null) {
            return issuanceTime.getDateTime();
        }

        return null;
    }

    /**
     * Gets a list of claims incorporated within the key binding payload,
     * which are not (yet) directly supported by the implementation.
     *
     * @return a list of {@link ClaimWrapper}s
     */
    public List<ClaimWrapper> getOtherKeyBindingPayloadClaims() {
        if (attestation.getKeyBindingPayload() != null && attestation.getKeyBindingPayload().getOtherClaim() != null) {
            return attestation.getKeyBindingPayload().getOtherClaim().stream().map(ClaimWrapper::new).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    /**
     * Gets attestation identifier provided in the attestation payload
     *
     * @return {@link String}
     */
    public String getIdentifier() {
        return getPayloadClaimTextValue(getPayload().getIdentifier());
    }

    /**
     * Gets attestation issuer as defined in the attestation payload
     *
     * @return {@link String}
     */
    public String getIssuer() {
        return getPayloadClaimTextValue(getPayload().getIssuer());
    }

    /**
     * Gets attestation subject as defined in the attestation payload
     *
     * @return {@link String}
     */
    public String getSubject() {
        return getPayloadClaimTextValue(getPayload().getSubject());
    }

    /**
     * Gets attestation audience as defined in the attestation payload
     *
     * @return {@link String}
     */
    public String getAudience() {
        return getPayloadClaimTextValue(getPayload().getAudience());
    }

    /**
     * Gets attestation issuance time as defined in the attestation payload
     *
     * @return {@link Date}
     */
    public Date getIssuedAt() {
        Date issuedAt = getPayloadClaimDateValue(getPayload().getIssuedAt());
        if (issuedAt != null) {
            return issuedAt;
        }
        ValidityInfoClaimWrapper attestationValidityInfo = getPayload().getValidityInfo();
        if (attestationValidityInfo != null) {
            return getPayloadClaimDateValue(attestationValidityInfo.getSigned());
        }
        return null;
    }

    /**
     * Gets attestation not before time as defined in the attestation payload
     *
     * @return {@link Date}
     */
    public Date getNotBefore() {
        Date notBefore = getPayloadClaimDateValue(getPayload().getNotBefore());
        if (notBefore != null) {
            return notBefore;
        }
        ValidityInfoClaimWrapper attestationValidityInfo = getPayload().getValidityInfo();
        if (attestationValidityInfo != null) {
            return getPayloadClaimDateValue(attestationValidityInfo.getValidFrom());
        }
        return null;
    }

    /**
     * Gets attestation expiration time as defined in the attestation payload
     *
     * @return {@link Date}
     */
    public Date getExpiration() {
        Date expirationTime = getPayloadClaimDateValue(getPayload().getExpiration());
        if (expirationTime != null) {
            return expirationTime;
        }
        ValidityInfoClaimWrapper attestationValidityInfo = getPayload().getValidityInfo();
        if (attestationValidityInfo != null) {
            return getPayloadClaimDateValue(attestationValidityInfo.getValidUntil());
        }
        return null;
    }

    /**
     * Gets attestation update time as defined in the attestation payload
     *
     * @return {@link Date}
     */
    public Date getUpdatedAt() {
        return getPayloadClaimDateValue(getPayload().getUpdatedAt());
    }

    /**
     * Gets attestation expected next update time
     *
     * @return {@link Date}
     */
    public Date getNextUpdate() {
        ValidityInfoClaimWrapper attestationValidityInfo = getPayload().getValidityInfo();
        if (attestationValidityInfo != null) {
            return getPayloadClaimDateValue(attestationValidityInfo.getExpectedUpdate());
        }
        return null;
    }

    /**
     * Gets category URN provided in the attestation payload
     *
     * @return {@link String}
     */
    public String getCategory() {
        return getPayloadClaimTextValue(getPayload().getCategory());
    }

    /**
     * Gets the attestation Qualification based on the category URN provided in the attestation payload
     *
     * @return {@link AttestationQualification}
     */
    public AttestationQualification getCategoryQualification() {
        String category = getCategory();
        if (EAACategory.EU_QEAA.getUrn().equals(category)) {
            return AttestationQualification.QEAA;
        } else if (EAACategory.EU_PUBEAA.getUrn().equals(category)) {
            return AttestationQualification.PUBEAA;
        } else if (category == null) {
            /*
             * EAA-5.2.2.1-01: SD-JWT VC attestations issued by attestations issuers registered in the European Union,
             * which are neither SD-JWT VC QAttestations nor SD-JWT VC PuB-Attestations, shall not include the category claim.
             */
            return AttestationQualification.EAA;
        } else {
            return AttestationQualification.UNKNOWN;
        }
    }

    /**
     * Gets attestation metadata URI (e.g. 'vct' claim) as defined in the attestation payload
     *
     * @return {@link String}
     */
    public String getVerifiableCredentialsTypeUri() {
        return getPayloadClaimTextValue(getPayload().getVerifiableCredentialsType());
    }

    /**
     * Gets Digest Algorithm used to compute the integrity material for the attestation metadata (when present)
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getVerifiableCredentialsTypeIntegrityDigestAlgorithm() {
        IntegrityClaimWrapper attestationVerifiableCredentialsTypeIntegrity = getPayload().getVerifiableCredentialsTypeIntegrity();
        if (attestationVerifiableCredentialsTypeIntegrity != null) {
            return attestationVerifiableCredentialsTypeIntegrity.getDigestAlgorithm();
        }
        return null;
    }

    /**
     * Gets the integrity material for the attestation metadata (when present)
     *
     * @return byte array representing the attestation's metadata hash
     */
    public byte[] getVerifiableCredentialsTypeIntegrityBytes() {
        IntegrityClaimWrapper attestationVerifiableCredentialsTypeIntegrity = getPayload().getVerifiableCredentialsTypeIntegrity();
        if (attestationVerifiableCredentialsTypeIntegrity != null) {
            return attestationVerifiableCredentialsTypeIntegrity.getDigestValue();
        }
        return null;
    }

    /**
     * Gets status index as defined in the attestation payload
     *
     * @return {@link Integer}
     */
    public Integer getStatusIndex() {
        StatusClaimWrapper status = getPayload().getStatus();
        if (status != null) {
            if (status.getIndex() != null) {
                return getPayloadClaimIntegerValue(status.getIndex());
            } else if (status.getStatusList() != null) {
                return getPayloadClaimIntegerValue(status.getStatusList().getIndex());
            }
        }
        return null;
    }

    /**
     * Gets status URI as defined in the attestation payload
     *
     * @return {@link String}
     */
    public String getStatusUri() {
        StatusClaimWrapper status = getPayload().getStatus();
        if (status != null) {
            if (status.getUri() != null) {
                return getPayloadClaimTextValue(status.getUri());
            } else if (status.getStatusList() != null) {
                return getPayloadClaimTextValue(status.getStatusList().getUri());
            }
        }
        return null;
    }

    /**
     * Gets a certificate containing the public key that signed or sealed the top-level
     * certificate in the x5chain element in the MSO revocation list structure
     *
     * @return {@link String}
     */
    public byte[] getStatusCertificate() {
        StatusClaimWrapper status = getPayload().getStatus();
        if (status != null && status.getStatusList() != null) {
            return getPayloadClaimByteValue(status.getStatusList().getCertificate());
        }
        return null;
    }

    /**
     * Gets status type as defined in the attestation payload
     *
     * @return {@link String}
     */
    public String getStatusType() {
        StatusClaimWrapper status = getPayload().getStatus();
        if (status != null) {
            return getPayloadClaimTextValue(status.getType());
        }
        return null;
    }

    /**
     * Gets status purpose as defined in the attestation payload
     *
     * @return {@link String}
     */
    public String getStatusPurpose() {
        StatusClaimWrapper status = getPayload().getStatus();
        if (status != null) {
            return getPayloadClaimTextValue(status.getPurpose());
        }
        return null;
    }

    /**
     * Gets attestation identifier to be used for the status verification using an Identifier List mechanism
     *
     * @return byte array
     */
    public byte[] getIdentifierListId() {
        StatusClaimWrapper status = getPayload().getStatus();
        if (status != null && status.getIdentifierList() != null) {
            return getPayloadClaimByteValue(status.getIdentifierList().getIdentifier());
        }
        return null;
    }

    /**
     * Gets status URI as defined in the attestation payload
     *
     * @return {@link String}
     */
    public String getIdentifierListUri() {
        StatusClaimWrapper status = getPayload().getStatus();
        if (status != null && status.getIdentifierList() != null) {
            return getPayloadClaimTextValue(status.getIdentifierList().getUri());
        }
        return null;
    }

    /**
     * Gets a certificate containing the public key that signed or sealed the top-level
     * certificate in the x5chain element in the MSO revocation list structure
     *
     * @return {@link String}
     */
    public byte[] getIdentifierListCertificate() {
        StatusClaimWrapper status = getPayload().getStatus();
        if (status != null && status.getIdentifierList() != null) {
            return getPayloadClaimByteValue(status.getIdentifierList().getCertificate());
        }
        return null;
    }

    /**
     * Gets attestation nonce when defined in the attestation payload
     *
     * @return {@link String}
     */
    public String getNonce() {
        return getPayloadClaimTextValue(getPayload().getNonce());
    }

    /**
     * Gets attestation device public key when defined in the attestation payload
     *
     * @return byte array containing an encoded device public key
     */
    public byte[] getDevicePublicKey() {
        DeviceKeyClaimWrapper attestationDeviceKey = getPayload().getDeviceKey();
        if (attestationDeviceKey != null) {
            return attestationDeviceKey.getPublicKey();
        }
        return null;
    }

    /**
     * Gets attestation device certificate token when defined in the attestation payload
     *
     * @return {@link CertificateWrapper}
     */
    public CertificateWrapper getDeviceCertificate() {
        DeviceKeyClaimWrapper attestationDeviceKey = getPayload().getDeviceKey();
        if (attestationDeviceKey != null) {
            List<CertificateWrapper> certificates = attestationDeviceKey.getCertificates();
            if (certificates != null && !certificates.isEmpty()) {
                return certificates.get(0);
            }
        }
        return null;
    }

    /**
     * Gets attestation device certificate chain when defined in the attestation payload
     *
     * @return a list of {@link CertificateWrapper}s
     */
    public List<CertificateWrapper> getDeviceCertificateChain() {
        DeviceKeyClaimWrapper attestationDeviceKey = getPayload().getDeviceKey();
        if (attestationDeviceKey != null) {
            return attestationDeviceKey.getCertificates();
        }
        return null;
    }

    /**
     * Gets attestation device certificate chain digests when defined in the attestation payload
     *
     * @return a list of {@link XmlDigestAlgoAndValue}s
     */
    public List<XmlDigestAlgoAndValue> getDeviceCertificateChainDigests() {
        DeviceKeyClaimWrapper attestationDeviceKey = getPayload().getDeviceKey();
        if (attestationDeviceKey != null) {
            return attestationDeviceKey.getCertificateDigests();
        }
        return null;
    }

    /**
     * Gets attestation device certificate chain KIDs when defined in the attestation payload
     *
     * @return a list of {@link String}s
     */
    public List<String> getDeviceCertificateKIDs() {
        DeviceKeyClaimWrapper attestationDeviceKey = getPayload().getDeviceKey();
        if (attestationDeviceKey != null) {
            return attestationDeviceKey.getKIDs();
        }
        return null;
    }

    /**
     * Gets attestation device certificate chain location URLs when defined in the attestation payload
     *
     * @return a list of {@link String}s
     */
    public List<String> getDeviceCertificateUrls() {
        DeviceKeyClaimWrapper attestationDeviceKey = getPayload().getDeviceKey();
        if (attestationDeviceKey != null) {
            return attestationDeviceKey.getX509URLs();
        }
        return null;
    }

    /**
     * Gets a list of namespaces authorized for the device key to sign or MAC
     *
     * @return a list of {@link String}s
     */
    public List<String> getDeviceKeyAuthorizedNamespaces() {
        DeviceKeyClaimWrapper attestationDeviceKey = getPayload().getDeviceKey();
        if (attestationDeviceKey != null) {
            return attestationDeviceKey.getAuthorizedNamespaces();
        }
        return null;
    }

    /**
     * Gets a map of namespaces and corresponding data elements the key is authorized to sign or MAC
     *
     * @return a map of {@link String} namespaces of lists of {@link String} data elements
     */
    public Map<String, List<String>> getDeviceKeyAuthorizedDataElements() {
        DeviceKeyClaimWrapper attestationDeviceKey = getPayload().getDeviceKey();
        if (attestationDeviceKey != null) {
            return attestationDeviceKey.getAuthorizedDataElements();
        }
        return null;
    }

    /**
     * Returns a list of statuses for the attestation
     *
     * @return a list of {@link AttestationRevocationWrapper}s
     */
    public List<AttestationRevocationWrapper> getAttestationRevocations() {
        List<AttestationRevocationWrapper> revocationWrappers = new ArrayList<>();
        List<XmlAttestationRevocationStatus> statuses = attestation.getAttestationRevocations();
        for (XmlAttestationRevocationStatus xmlAttestationRevocationStatus : statuses) {
            revocationWrappers.add(new AttestationRevocationWrapper(xmlAttestationRevocationStatus));
        }
        return revocationWrappers;
    }

    /**
     * Gets a version of the MobileSecurityObject.
     *
     * @return {@link String}
     */
    public String getVersion() {
        return getPayloadClaimTextValue(getPayload().getVersion());
    }

    /**
     * Gets user's full name when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getFullName() {
        return getPayloadClaimTextValue(getPayload().getFullName());
    }

    /**
     * Gets user's first name when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getGivenName() {
        return getPayloadClaimTextValue(getPayload().getGivenName());
    }

    /**
     * Gets user's last or family name when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getFamilyName() {
        return getPayloadClaimTextValue(getPayload().getFamilyName());
    }

    /**
     * Gets user's middle name when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getMiddleName() {
        return getPayloadClaimTextValue(getPayload().getMiddleName());
    }

    /**
     * Gets user's alternative name when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getNickname() {
        return getPayloadClaimTextValue(getPayload().getNickname());
    }

    /**
     * Gets user's preferred or short name when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getShortName() {
        return getPayloadClaimTextValue(getPayload().getShortName());
    }

    /**
     * Gets user's profile URL when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getProfileUrl() {
        return getPayloadClaimTextValue(getPayload().getProfileUrl());
    }

    /**
     * Gets user's picture URL when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getPictureUrl() {
        return getPayloadClaimTextValue(getPayload().getPictureUrl());
    }

    /**
     * Gets user's website when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getWebsiteUrl() {
        return getPayloadClaimTextValue(getPayload().getWebsiteUrl());
    }

    /**
     * Gets user's email when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getEmail() {
        return getPayloadClaimTextValue(getPayload().getEmail());
    }

    /**
     * Gets whether the user's website has been verified if defined within attestation Payload claims
     *
     * @return {@link Boolean}
     */
    public Boolean getEmailVerified() {
        return getPayloadClaimBooleanValue(getPayload().getEmailVerified());
    }

    /**
     * Gets user's gender when defined within attestation Payload claims
     *
     * @return {@link Integer}
     */
    public Integer getGender() {
        return getPayloadClaimIntegerValue(getPayload().getGender());
    }

    /**
     * Gets user's birthdate when defined within attestation Payload claims
     *
     * @return {@link Date}
     */
    public Date getBirthdate() {
        if (getPayload().getBirthdate() != null) {
            return getPayloadClaimDateValue(getPayload().getBirthdate().getBirthdate());
        }
        return null;
    }

    /**
     * Gets an 8 digit flag to denote the location of the mask in YYYYMMDD format within the user's birthdate.
     *
     * @return {@link String}
     */
    public String getBirthdateApproximateMask() {
        if (getPayload().getBirthdate() != null) {
            return getPayloadClaimTextValue(getPayload().getBirthdate().getApproximateMask());
        }
        return null;
    }

    /**
     * Gets user's timezone when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getTimezone() {
        return getPayloadClaimTextValue(getPayload().getTimezone());
    }

    /**
     * Gets user's locale when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getLocale() {
        return getPayloadClaimTextValue(getPayload().getLocale());
    }

    /**
     * Gets user's full postal address, formatted, when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getPostalAddress() {
        AddressClaimWrapper userAddress = getPayload().getAddress();
        if (userAddress != null) {
            return getPayloadClaimTextValue(userAddress.getPostalAddress());
        }
        return null;
    }

    /**
     * Gets user's city address when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getAddressCity() {
        AddressClaimWrapper userAddress = getPayload().getAddress();
        if (userAddress != null) {
            return getPayloadClaimTextValue(userAddress.getCity());
        }
        ClaimWrapper residentAddressCity = getPayload().getResidentAddressCity();
        if (residentAddressCity != null) {
            return getPayloadClaimTextValue(residentAddressCity);
        }
        return null;
    }

    /**
     * Gets user's state or region address when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getAddressStateOrProvince() {
        AddressClaimWrapper userAddress = getPayload().getAddress();
        if (userAddress != null) {
            return getPayloadClaimTextValue(userAddress.getStateOrProvince());
        }
        ClaimWrapper residentAddressState = getPayload().getResidentAddressState();
        if (residentAddressState != null) {
            return getPayloadClaimTextValue(residentAddressState);
        }
        return null;
    }

    /**
     * Gets user's postal code address when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getAddressPostalCode() {
        AddressClaimWrapper userAddress = getPayload().getAddress();
        if (userAddress != null) {
            return getPayloadClaimTextValue(userAddress.getPostalCode());
        }
        ClaimWrapper residentAddressPostalCode = getPayload().getResidentAddressPostalCode();
        if (residentAddressPostalCode != null) {
            return getPayloadClaimTextValue(residentAddressPostalCode);
        }
        return null;
    }

    /**
     * Gets user's country address when defined within attestation Payload claims.
     * NOTE: The returned value is usually represented by 2-letter ISO country code.
     *
     * @return {@link String}
     */
    public String getAddressCountry() {
        AddressClaimWrapper userAddress = getPayload().getAddress();
        if (userAddress != null) {
            return getPayloadClaimTextValue(userAddress.getCountry());
        }
        ClaimWrapper residentAddressCountry = getPayload().getResidentAddressCountry();
        if (residentAddressCountry != null) {
            return getPayloadClaimTextValue(residentAddressCountry);
        }
        return null;
    }

    /**
     * Gets user's street address when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getStreetAddress() {
        AddressClaimWrapper userAddress = getPayload().getAddress();
        if (userAddress != null) {
            return getPayloadClaimTextValue(userAddress.getStreetAddress());
        }
        ClaimWrapper postalAddress = getPayload().getResidentPostalAddress();
        if (postalAddress != null) {
            return getPayloadClaimTextValue(postalAddress);
        }
        return null;
    }

    /**
     * Gets user's phone number when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getPhoneNumber() {
        return getPayloadClaimTextValue(getPayload().getPhoneNumber());
    }

    /**
     * Gets whether the user's phone number has been verified if defined within attestation Payload claims
     *
     * @return {@link Boolean}
     */
    public Boolean getPhoneNumberVerified() {
        return getPayloadClaimBooleanValue(getPayload().getPhoneNumberVerified());
    }

    /**
     * Gets user's complete place of birth when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getPlaceOfBirth() {
        PlaceOfBirthClaimWrapper userPlaceOfBirth = getPayload().getPlaceOfBirth();
        if (userPlaceOfBirth != null && userPlaceOfBirth.isText()) {
            return getPayloadClaimTextValue(userPlaceOfBirth);
        }
        return null;
    }

    /**
     * Gets user's country of birth when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getPlaceOfBirthCountry() {
        PlaceOfBirthClaimWrapper userPlaceOfBirth = getPayload().getPlaceOfBirth();
        if (userPlaceOfBirth != null) {
            return getPayloadClaimTextValue(userPlaceOfBirth.getCountry());
        }
        return null;
    }

    /**
     * Gets user's state or region of birth when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getPlaceOfBirthRegion() {
        PlaceOfBirthClaimWrapper userPlaceOfBirth = getPayload().getPlaceOfBirth();
        if (userPlaceOfBirth != null) {
            return getPayloadClaimTextValue(userPlaceOfBirth.getRegion());
        }
        return null;
    }

    /**
     * Gets user's city of birth when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getPlaceOfBirthCity() {
        PlaceOfBirthClaimWrapper userPlaceOfBirth = getPayload().getPlaceOfBirth();
        if (userPlaceOfBirth != null) {
            return getPayloadClaimTextValue(userPlaceOfBirth.getCity());
        }
        return null;
    }

    /**
     * Gets user's nationalities list when defined within attestation Payload claims.
     * NOTE: The values are usually represented by 3-letter nationality codes.
     *
     * @return a list of {@link String}s
     */
    public List<String> getNationalities() {
        return getPayloadClaimArrayAsStringsValue(getPayload().getNationalities());
    }

    /**
     * Gets user's last or family name at birth when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getBirthFamilyName() {
        return getPayloadClaimTextValue(getPayload().getBirthFamilyName());
    }

    /**
     * Gets user's first name at birth when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getBirthGivenName() {
        return getPayloadClaimTextValue(getPayload().getBirthGivenName());
    }

    /**
     * Gets user's middle name at birth when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getBirthMiddleName() {
        return getPayloadClaimTextValue(getPayload().getBirthMiddleName());
    }

    /**
     * Gets user's preferred salutation when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getSalutation() {
        return getPayloadClaimTextValue(getPayload().getSalutation());
    }

    /**
     * Gets the name(s) which holder was born.
     *
     * @return {@link String}
     */
    public String getBirthFullName() {
        return getPayloadClaimTextValue(getPayload().getBirthFullName());
    }

    /**
     * Gets user's title when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getTitle() {
        return getPayloadClaimTextValue(getPayload().getTitle());
    }

    /**
     * Gets user's mobile phone number when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getMobilePhoneNumber() {
        return getPayloadClaimTextValue(getPayload().getMobilePhoneNumber());
    }

    /**
     * Gets user's scenic name or pseudonym, they are known as, when defined within attestation Payload claims
     *
     * @return {@link String}
     */
    public String getPseudonym() {
        return getPayloadClaimTextValue(getPayload().getPseudonym());
    }

    /* mdoc claims */

    /**
     * Gets issuing authority name.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link String}
     */
    public String getDocumentIssuingAuthority() {
        return getPayloadClaimTextValue(getPayload().getDocumentIssuingAuthority());
    }

    /**
     * Gets alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory
     *
     * @return {@link String}
     */
    public String getDocumentIssuingAuthorityCountry() {
        return getPayloadClaimTextValue(getPayload().getDocumentIssuingAuthorityCountry());
    }

    /**
     * Gets a country subdivision code of the jurisdiction that issued the mDL as defined in
     * ISO 3166-2:2020, Clause 8. The first part of the code shall be the same as the value for issuing_country.
     *
     * @return {@link String}
     */
    public String getDocumentIssuingAuthorityJurisdiction() {
        return getPayloadClaimTextValue(getPayload().getDocumentIssuingAuthorityJurisdiction());
    }

    /**
     * An audit control number assigned by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link String}
     */
    public String getPersonalAdministrativeNumber() {
        return getPayloadClaimTextValue(getPayload().getPersonalAdministrativeNumber());
    }

    /**
     * Gets the distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F.
     * If no applicable distinguishing sign is available in ISO/IEC 18013-1, an IA may
     * use an empty identifier or another identifier by which it is internationally recognized.
     * In this case the IA should ensure there is no collision with other IA’s.
     *
     * @return {@link String}
     */
    public String getDocumentIssuingAuthorityCountryUNDistinguishingSign() {
        return getPayloadClaimTextValue(getPayload().getDocumentIssuingAuthorityUNDistinguishingSign());
    }

    /**
     * Gets the number assigned or calculated by the issuing authority.
     * The value shall only use latin1 characters and shall have a maximum length of 150 characters.
     *
     * @return {@link String}
     */
    public String getDocumentNumber() {
        return getPayloadClaimTextValue(getPayload().getDocumentNumber());
    }

    /**
     * Gets the document type claimed by the attestation (through a selectively disclosable property).
     *
     * @return {@link String}
     */
    public String getClaimedDocumentType() {
        return getPayloadClaimTextValue(getPayload().getClaimedDocumentType());
    }

    /**
     * Gets a reproduction of the mDL holder’s portrait.
     *
     * @return byte array
     */
    public byte[] getPortrait() {
        return getPayloadClaimByteValue(getPayload().getPortrait());
    }

    /**
     * Gets the categories of vehicles/restrictions/conditions contain information describing the driving privileges
     * of the mDL holder.
     *
     * @return {@link DrivingPrivilegesClaimWrapper}
     */
    public DrivingPrivilegesClaimWrapper getDrivingPrivileges() {
        return getPayload().getDrivingPrivileges();
    }

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link Integer}
     */
    public Integer getHeight() {
        return getPayloadClaimIntegerValue(getPayload().getHeight());
    }

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link Integer}
     */
    public Integer getWeight() {
        return getPayloadClaimIntegerValue(getPayload().getWeight());
    }

    /**
     * Gets the mDL holder’s eye colour. The value shall be one of the following: “black”, “blue”,
     * “brown”, “dichromatic”, “grey”, “green”, “hazel”, “maroon”, “pink”, “unknown”.
     *
     * @return {@link String}
     */
    public String getEyeColour() {
        return getPayloadClaimTextValue(getPayload().getEyeColour());
    }

    /**
     * Gets the mDL holder’s hair colour. The value shall be one of the following: “bald”, “black”,
     * “blond”, “brown”, “grey”, “red”, “auburn”, “sandy”, “white”, “unknown”.
     *
     * @return {@link String}
     */
    public String getHairColour() {
        return getPayloadClaimTextValue(getPayload().getHairColour());
    }

    /**
     * Gets the date when portrait was taken.
     *
     * @return {@link Date}
     */
    public Date getPortraitCaptureDate() {
        return getPayloadClaimDateValue(getPayload().getPortraitCaptureDate());
    }

    /**
     * Gets the date the age of the mDL holder
     *
     * @return {@link Integer}
     */
    public Integer getAgeInYears() {
        return getPayloadClaimIntegerValue(getPayload().getAgeInYears());
    }

    /**
     * Gets the year when the mDL holder was born
     *
     * @return {@link Integer}
     */
    public Integer getAgeBirthYear() {
        return getPayloadClaimIntegerValue(getPayload().getAgeBirthYear());
    }

    /**
     * Returns the claim value whether the age of an attestation's holder is over the {@code age}.
     * NOTE: if there is no claim provided for the requested age, NULL is returned.
     *
     * @param age integer age to verify against
     * @return {@link Boolean}
     */
    public Boolean isAgeOver(int age) {
        AgeEqualOrOverClaimWrapper holderAgeEqualOrOver = getPayload().getAgeEqualOrOver();
        if (holderAgeEqualOrOver != null) {
            Boolean result = isAgeOver(holderAgeEqualOrOver.getAgeEqualOrOverList(), age);
            if (result != null) {
                return result;
            }
        }
        return isAgeOver(getPayload().getAgeOverList(), age);
    }

    private Boolean isAgeOver(List<AgeOverNNClaimWrapper> ageOverClaimsList, int age) {
        if (ageOverClaimsList != null && !ageOverClaimsList.isEmpty()) {
            for (AgeOverNNClaimWrapper ageOverNNClaim : ageOverClaimsList) {
                if (age == ageOverNNClaim.getAge()) {
                    return getPayloadClaimBooleanValue(ageOverNNClaim);
                }
            }
        }
        return null;
    }

    /**
     * Returns the biometric template for thr given value.
     * The list of supported values is defined in ISO/IEC 18013-2:2020.
     * NOTE: if there is no claim provided for the requested type, NULL is returned.
     *
     * @param type {@link String} type to get biometric template for
     * @return byte array
     */
    public byte[] getBiometricTemplate(String type) {
        if (type == null) {
            return null;
        }
        /*
         * A biometric template identifier has the format biometric_template_xx
         * where xx shall be replaced with the corresponding “Abstract value name” found in ISO/IEC 19785-3:2020,
         * Table 7, according to the following convention: capitalized characters are replaced with their
         * lowercase equivalent and spaces or non-alphanumeric characters are replaced by underscores (_).
         */
        type = normalizeType(type);
        List<BiometricTemplateXXClaimWrapper> biometricTemplateList = getPayload().getBiometricTemplateList();
        if (biometricTemplateList != null && !biometricTemplateList.isEmpty()) {
            for (BiometricTemplateXXClaimWrapper biometricTemplate : biometricTemplateList) {
                if (type.equals(normalizeType(biometricTemplate.getType()))) {
                    return getPayloadClaimByteValue(biometricTemplate);
                }
            }
        }
        return null;
    }

    private String normalizeType(String type) {
        if (type == null) {
            return null;
        }
        type = type.toLowerCase();
        return type.replaceAll("[^\\p{L}\\p{Nd}]+", "_");
    }

    /**
     * Gets an image of the signature or usual mark of the mDL holder, see 7.2.7 ISO/IEC 18013-5.
     *
     * @return byte array
     */
    public byte[] getSignatureUsualMark() {
        return getPayloadClaimByteValue(getPayload().getSignatureUsualMark());
    }

    /**
     * Gets a reproduction of the holder’s fingerprint data (TBC).
     *
     * @return byte array
     */
    public byte[] getFingerprint() {
        return getPayloadClaimByteValue(getPayload().getFingerprint());
    }

    /**
     * Gets a business name of the holder.
     *
     * @return {@link String}
     */
    public String getBusinessName() {
        return getPayloadClaimTextValue(getPayload().getBusinessName());
    }

    /**
     * Gets a name of legal person.
     *
     * @return {@link String}
     */
    public String getOrganizationName() {
        return getPayloadClaimTextValue(getPayload().getOrganizationName());
    }

    /**
     * Gets the profession of the holder.
     *
     * @return {@link String}
     */
    public String getProfession() {
        return getPayloadClaimTextValue(getPayload().getProfession());
    }

    /**
     * Gets the father of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipFather() {
        return getPayloadClaimTextValue(getPayload().getRelationshipFather());
    }

    /**
     * Gets the mother of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipMother() {
        return getPayloadClaimTextValue(getPayload().getRelationshipMother());
    }

    /**
     * Gets the parent of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipParent() {
        return getPayloadClaimTextValue(getPayload().getRelationshipParent());
    }

    /**
     * Gets the son of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipSon() {
        return getPayloadClaimTextValue(getPayload().getRelationshipSon());
    }

    /**
     * Gets the daughter of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipDaughter() {
        return getPayloadClaimTextValue(getPayload().getRelationshipDaughter());
    }

    /**
     * Gets the brother of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipBrother() {
        return getPayloadClaimTextValue(getPayload().getRelationshipBrother());
    }

    /**
     * Gets the sister of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipSister() {
        return getPayloadClaimTextValue(getPayload().getRelationshipSister());
    }

    /**
     * Gets the sibling of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipSibling() {
        return getPayloadClaimTextValue(getPayload().getRelationshipSibling());
    }

    /**
     * Gets the spouse of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipSpouse() {
        return getPayloadClaimTextValue(getPayload().getRelationshipSpouse());
    }

    /**
     * Gets the father-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipFatherInLaw() {
        return getPayloadClaimTextValue(getPayload().getRelationshipFatherInLaw());
    }

    /**
     * Gets the mother-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipMotherInLaw() {
        return getPayloadClaimTextValue(getPayload().getRelationshipMotherInLaw());
    }

    /**
     * Gets the parent-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipParentInLaw() {
        return getPayloadClaimTextValue(getPayload().getRelationshipParentInLaw());
    }

    /**
     * Gets the son-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipSonInLaw() {
        return getPayloadClaimTextValue(getPayload().getRelationshipSonInLaw());
    }

    /**
     * Gets the daughter-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipDaughterInLaw() {
        return getPayloadClaimTextValue(getPayload().getRelationshipDaughterInLaw());
    }

    /**
     * Gets the child-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipChildInLaw() {
        return getPayloadClaimTextValue(getPayload().getRelationshipChildInLaw());
    }

    /**
     * Gets the parental authority of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipParentalAuthority() {
        return getPayloadClaimTextValue(getPayload().getRelationshipParentalAuthority());
    }

    /**
     * Gets the legal representative of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipLegalRepresentative() {
        return getPayloadClaimTextValue(getPayload().getRelationshipLegalRepresentative());
    }

    /**
     * Gets the voluntary agent of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipAgent() {
        return getPayloadClaimTextValue(getPayload().getRelationshipAgent());
    }

    /**
     * Gets the date when the data (e.g. a PID) was issued
     *
     * @return {@link Date}
     */
    public Date getAdministrativeIssuanceDate() {
        return getPayloadClaimDateValue(getPayload().getAdministrativeIssuanceDate());
    }

    /**
     * Gets the date when the data (e.g. a PID) will expire
     *
     * @return {@link Date}
     */
    public Date getAdministrativeExpirationDate() {
        return getPayloadClaimDateValue(getPayload().getAdministrativeExpirationDate());
    }

    /**
     * Gets the URL at which a machine-readable version of the trust anchor to be used for
     * verifying the PID can be found or looked up.
     *
     * @return {@link String}
     */
    public String getTrustAnchor() {
        return getPayloadClaimTextValue(getPayload().getTrustAnchor());
    }

    /**
     * Gets the name of the street where the user to whom the person identification data relates currently resides.
     *
     * @return {@link String}
     */
    public String getResidentAddressStreet() {
        return getPayloadClaimTextValue(getPayload().getResidentAddressStreet());
    }

    /**
     * Gets the house number where the user to whom the person identification data relates currently resides,
     * including any affix or suffix.
     *
     * @return {@link String}
     */
    public String getResidentAddressHouseNumber() {
        return getPayloadClaimTextValue(getPayload().getResidentAddressHouseNumber());
    }

    /**
     * Gets the name of the city where the user to whom the person identification data relates currently resides.
     *
     * @return {@link String}
     */
    public String getResidentAddressCity() {
        return getPayloadClaimTextValue(getPayload().getResidentAddressCity());
    }

    /**
     * Gets the name of the state where the user to whom the person identification data relates currently resides.
     *
     * @return {@link String}
     */
    public String getResidentAddressState() {
        return getPayloadClaimTextValue(getPayload().getResidentAddressState());
    }

    /**
     * Gets the postal code of the address where the user to whom the person identification data relates currently resides.
     *
     * @return {@link String}
     */
    public String getResidentAddressPostalCode() {
        return getPayloadClaimTextValue(getPayload().getResidentAddressPostalCode());
    }

    /**
     * Gets the name of the country where the user to whom the person identification data relates currently resides.
     *
     * @return {@link String}
     */
    public String getResidentAddressCountry() {
        return getPayloadClaimTextValue(getPayload().getResidentAddressCountry());
    }

    /**
     * Gets the full address where the user to whom the person identification data relates currently resides.
     *
     * @return {@link String}
     */
    public String getResidentPostalAddress() {
        return getPayloadClaimTextValue(getPayload().getResidentPostalAddress());
    }

    /* ETSI TS 119 472-1 "5 Implementation of attestation based on SD-JWT VC" header parameters */

    /**
     * Gets the registration identifier of the legal entity on whose behalf the attestation has been issued.
     *
     * @return {@link String}
     */
    public String getIssuingRegistrationIdentifier() {
        return getPayloadClaimTextValue(getPayload().getIssuingAuthorityRegistrationIdentifier());
    }

    /**
     * Gets the signal indicating that the attestation shall be used only once, and that it shall not be retained for future use.
     *
     * @return {@link Boolean}
     */
    public Boolean getOneTimeUse() {
        return getPayloadClaimBooleanValue(getPayload().getOneTimeUse());
    }

    /**
     * Gets the attestation short-lived component indicating that the validity period of the attestation is so short that
     * it shall not be necessary to check its revocation status.
     *
     * @return {@link Boolean}
     */
    public Boolean getShortLived() {
        return getPayloadClaimBooleanValue(getPayload().getShortLived());
    }

    /**
     * Gets the identifier of the attribute subject, which shall associate the attributes to this attribute subject
     *
     * @return {@link String}
     */
    public String getAttestedAttributesSubjectId() {
        AttestedAttributesSubjectClaimWrapper attestedAttributesSubject = getPayload().getAttestedAttributesSubject();
        if (attestedAttributesSubject != null) {
            return getPayloadClaimTextValue(attestedAttributesSubject.getSubjectId());
        }
        return null;
    }

    /**
     * Gets the family name of the attribute subject, which shall associate the attributes to this attribute subject
     *
     * @return {@link String}
     */
    public String getAttestedAttributesSubjectFamilyName() {
        AttestedAttributesSubjectClaimWrapper attestedAttributesSubject = getPayload().getAttestedAttributesSubject();
        if (attestedAttributesSubject != null && attestedAttributesSubject.getSubjectId() != null) {
            return getPayloadClaimTextValue(attestedAttributesSubject.getSubjectId().getFamilyName());
        }
        return null;
    }

    /**
     * Gets the given name of the attribute subject, which shall associate the attributes to this attribute subject
     *
     * @return {@link String}
     */
    public String getAttestedAttributesSubjectGivenName() {
        AttestedAttributesSubjectClaimWrapper attestedAttributesSubject = getPayload().getAttestedAttributesSubject();
        if (attestedAttributesSubject != null && attestedAttributesSubject.getSubjectId() != null) {
            return getPayloadClaimTextValue(attestedAttributesSubject.getSubjectId().getGivenName());
        }
        return null;
    }

    /**
     * Gets the document number of the attribute subject, which shall associate the attributes to this attribute subject
     *
     * @return {@link String}
     */
    public String getAttestedAttributesSubjectDocumentNumber() {
        AttestedAttributesSubjectClaimWrapper attestedAttributesSubject = getPayload().getAttestedAttributesSubject();
        if (attestedAttributesSubject != null && attestedAttributesSubject.getSubjectId() != null) {
            return getPayloadClaimTextValue(attestedAttributesSubject.getSubjectId().getDocumentNumber());
        }
        return null;
    }

    /**
     * Gets the claim for associating a set of attributes to one entity different than the attestation subject.
     *
     * @return {@link String}
     */
    public String getAttestedAttributesSubjectPseudonym() {
        AttestedAttributesSubjectClaimWrapper attestedAttributesSubject = getPayload().getAttestedAttributesSubject();
        if (attestedAttributesSubject != null) {
            return getPayloadClaimTextValue(attestedAttributesSubject.getSubjectPseudonym());
        }
        return null;
    }

    /**
     * Gets the attributes associated to the attribute subject whose identifier appears in the sub_id member or
     * whose pseudonym appears in the sub_aka member.
     *
     * @return {@link String}
     */
    public List<String> getAttestedAttributes() {
        AttestedAttributesSubjectClaimWrapper attestedAttributesSubject = getPayload().getAttestedAttributesSubject();
        if (attestedAttributesSubject != null) {
            return getPayloadClaimArrayAsStringsValue(attestedAttributesSubject.getAttributes());
        }
        return null;
    }

    /**
     * Gets a list of claims incorporated within the attestation Payload or provided as disclosures,
     * which are not (yet) directly supported by the implementation.
     *
     * @return a list of {@link ClaimWrapper}s
     */
    public List<ClaimWrapper> getOtherClaims() {
        return getPayload().getOtherClaims();
    }

    /**
     * This method returns a claim using the header name used within the attestation payload
     *
     * @param headerName {@link String} representing the header name
     * @return {@link ClaimWrapper} if present, or NULL otherwise
     */
    public ClaimWrapper getClaimByHeaderName(String headerName) {
        if (headerName == null) {
            return null;
        }
        List<ClaimWrapper> attestationPayloadClaims = getAllAttestationPayloadClaims();
        if (attestation != null && !attestationPayloadClaims.isEmpty()) {
            for (ClaimWrapper claim : attestationPayloadClaims) {
                if (headerName.equals(claim.getName())) {
                    return claim;
                }
            }
        }
        return null;
    }

    /**
     * This method returns all claims that have been selectively disclosed and identified on the attestation
     * (i.e. provided in the form of disclosures).
     *
     * @return a list of {@link ClaimWrapper}s
     */
    public List<ClaimWrapper> getSelectivelyDisclosableClaims() {
        final List<ClaimWrapper> result = new ArrayList<>();
        List<ClaimWrapper> attestationPayloadClaims = getAllAttestationPayloadClaims();
        if (attestation != null && !attestationPayloadClaims.isEmpty()) {
            for (ClaimWrapper claim : attestationPayloadClaims) {
                result.addAll(getSelectivelyDisclosableClaimsRecursively(claim));
            }
        }
        return result;
    }

    private List<ClaimWrapper> getSelectivelyDisclosableClaimsRecursively(ClaimWrapper claimWrapper) {
        List<ClaimWrapper> result = new ArrayList<>();
        if (claimWrapper.isSelectivelyDisclosable()) {
            result.add(claimWrapper);
        }
        if (claimWrapper.isList()) {
            for (ClaimWrapper listItem : claimWrapper.getList()) {
                result.addAll(getSelectivelyDisclosableClaimsRecursively(listItem));
            }
        } else if (claimWrapper.isMap()) {
            for (ClaimWrapper entryItem : claimWrapper.getMap().values()) {
                result.addAll(getSelectivelyDisclosableClaimsRecursively(entryItem));
            }
        }
        return result;
    }

    private String getPayloadClaimTextValue(ClaimWrapper xmlDisclosableClaim) {
        if (xmlDisclosableClaim == null) {
            return null;
        }
        return xmlDisclosableClaim.getText();
    }

    private BigInteger getPayloadClaimNumberValue(ClaimWrapper xmlDisclosableClaim) {
        if (xmlDisclosableClaim == null) {
            return null;
        }
        return xmlDisclosableClaim.getNumber();
    }

    private Integer getPayloadClaimIntegerValue(ClaimWrapper xmlDisclosableClaim) {
        BigInteger bigIntegerValue = getPayloadClaimNumberValue(xmlDisclosableClaim);
        if (bigIntegerValue != null) {
            return bigIntegerValue.intValue();
        }
        return null;
    }

    private Date getPayloadClaimDateValue(ClaimWrapper xmlDisclosableClaim) {
        if (xmlDisclosableClaim == null) {
            return null;
        }
        return xmlDisclosableClaim.getDateTime();
    }

    private Boolean getPayloadClaimBooleanValue(ClaimWrapper xmlDisclosableClaim) {
        if (xmlDisclosableClaim == null) {
            return null;
        }
        if (xmlDisclosableClaim.isNull()) {
            return true; // handle as a true flag
        }
        return xmlDisclosableClaim.isBoolean() && Boolean.TRUE.equals(xmlDisclosableClaim.getBoolean());
    }

    private List<String> getPayloadClaimArrayAsStringsValue(ClaimWrapper xmlDisclosableClaim) {
        if (xmlDisclosableClaim == null) {
            return null;
        }
        if (xmlDisclosableClaim.isText()) {
            return Collections.singletonList(xmlDisclosableClaim.getText());
        } else if (xmlDisclosableClaim.isList()) {
            return xmlDisclosableClaim.getList().stream().map(ClaimWrapper::getText).filter(Objects::nonNull).collect(Collectors.toList());
        } else {
            throw new IllegalStateException(String.format("Unsupported type '%s'!", xmlDisclosableClaim.getClass().getSimpleName()));
        }
    }

    private byte[] getPayloadClaimByteValue(ClaimWrapper xmlDisclosableClaim) {
        if (xmlDisclosableClaim == null) {
            return null;
        }
        return xmlDisclosableClaim.getBinary();
    }

    /**
     * Gets a list of all disclosable claims present within an attestation Payload
     * NOTE: The method retrieves claims from the root payload level only
     *
     * @return a list of {@link ClaimWrapper}s
     */
    public List<ClaimWrapper> getAllAttestationPayloadClaims() {
        return getPayload().getAllAttestationPayloadClaims();
    }

    /**
     * Gets a list of names (keys) for all disclosable claims present within an attestation Payload
     * NOTE: The method retrieves names from the root payload level only
     *
     * @return a list of {@link ClaimWrapper}s
     */
    public List<String> getAllAttestationPayloadClaimNames() {
        return getAllAttestationPayloadClaims().stream().map(ClaimWrapper::getName).filter(Objects::nonNull).collect(Collectors.toList());
    }

    /**
     * (Mdoc only) Gets a set of all claim namespaces
     *
     * @return a set of {@link String}s
     */
    public Set<String> getAllClaimNamespaces() {
        return getAllAttestationPayloadClaims().stream().map(ClaimWrapper::getNamespace).filter(Objects::nonNull).collect(Collectors.toSet());
    }

    /**
     * Gets profile of the attestation
     *
     * @return {@link AttestationProfile}
     */
    public AttestationProfile getAttestationProfile() {
        return attestation.getProfile();
    }

    @Override
    public byte[] getBinaries() {
        // TODO : add support
        return null;
    }

}
