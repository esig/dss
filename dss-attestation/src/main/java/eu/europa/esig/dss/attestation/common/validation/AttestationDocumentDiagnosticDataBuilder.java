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
package eu.europa.esig.dss.attestation.common.validation;

import eu.europa.esig.dss.diagnostic.jaxb.XmlAddressClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAgeEqualOrOverClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAgeOverNNClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestedAttributesSubjectClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestedAttributesSubjectIdClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAuthorizedDataElements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBiometricTemplateXXClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBirthdateClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCredentialSubjectClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDeviceKeyClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDisclosableClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDrivingPrivilegeClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDrivingPrivilegeCodeClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDrivingPrivilegeCodesClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDrivingPrivilegesClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationDocument;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationPayload;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationPresentationInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationRevocationStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationSubject;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIdentifierListClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIntegrityClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlKeyAuthorizations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlKeyBindingPayload;
import eu.europa.esig.dss.diagnostic.jaxb.XmlKeyBindingSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlVerifiableCredentialsTypeClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPlaceOfBirthClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStatusClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStatusListClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlValidityInfoClaim;
import eu.europa.esig.dss.diagnostic.jaxb.XmlX509Certificate;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.attestation.DisclosureValidation;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAddress;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAgeEqualOrOver;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAgeOverNN;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAttestedAttributesSubject;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAttestedAttributesSubjectId;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimBiometricTemplateXX;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimBirthDate;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimCredentialSubject;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDeviceKey;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDrivingPrivilege;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDrivingPrivilegeCode;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDrivingPrivilegeCodes;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDrivingPrivileges;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimIdentifierList;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimIntegrity;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimPlaceOfBirth;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimStatus;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimStatusList;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimValidityInfo;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.TokenComparator;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.attestation.AttestationPresentation;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationToken;
import eu.europa.esig.dss.spi.attestation.KeyBindingSignaturePayload;
import eu.europa.esig.dss.spi.attestation.AttestationPayload;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.CandidatesForSigningCertificate;
import eu.europa.esig.dss.spi.x509.CertificateValidity;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.diagnostic.DiagnosticDataBuilder;
import eu.europa.esig.dss.validation.reports.diagnostic.SignedDocumentDiagnosticDataBuilder;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Builds DiagnosticData for validation of an attestation presentation document
 *
 */
public class AttestationDocumentDiagnosticDataBuilder extends SignedDocumentDiagnosticDataBuilder {

    /** The attestation presentation */
    protected AttestationPresentation attestationPresentation;

    /** Collection of attestation revocation tokens acquired during the validation */
    protected Collection<AttestationRevocationToken> attestationRevocationTokens;

    /** Builder used to build a signature object */
    private SignedDocumentDiagnosticDataBuilder signatureDiagnosticDataBuilder;

    /** The cached map of attestations */
    protected Map<String, XmlAttestation> xmlAttestationMap = new HashMap<>();

    /** The cached map of attestation revocation tokens */
    protected Map<String, XmlAttestationRevocationToken> xmlAttestationRevocationTokenMap = new HashMap<>();

    /**
     * Default constructor
     */
    public AttestationDocumentDiagnosticDataBuilder() {
        // empty
    }

    /**
     * Sets found attestation presentation
     *
     * @param attestationPresentation {@code AttestationPresentation}
     * @return this builder
     */
    public AttestationDocumentDiagnosticDataBuilder foundAttestationPresentation(AttestationPresentation attestationPresentation) {
        this.attestationPresentation = attestationPresentation;
        return this;
    }

    /**
     * Sets found attestation revocation tokens
     *
     * @param attestationRevocationTokens a collection of {@code AttestationRevocationToken}s
     * @return this builder
     */
    public AttestationDocumentDiagnosticDataBuilder foundAttestationRevocationTokens(Collection<AttestationRevocationToken> attestationRevocationTokens) {
        this.attestationRevocationTokens = attestationRevocationTokens;
        return this;
    }

    /**
     * Sets a builder for a signature object
     *
     * @param signatureDiagnosticDataBuilder {@link SignedDocumentDiagnosticDataBuilder}
     * @return {@link AttestationDocumentDiagnosticDataBuilder}
     */
    public AttestationDocumentDiagnosticDataBuilder setSignatureDiagnosticDataBuilder(SignedDocumentDiagnosticDataBuilder signatureDiagnosticDataBuilder) {
        this.signatureDiagnosticDataBuilder = signatureDiagnosticDataBuilder;
        return this;
    }

    @Override
    public DiagnosticDataBuilder tokenIdentifierProvider(TokenIdentifierProvider identifierProvider) {
        super.tokenIdentifierProvider(identifierProvider);
        if (signatureDiagnosticDataBuilder != null) {
            signatureDiagnosticDataBuilder.tokenIdentifierProvider(identifierProvider);
        }
        return this;
    }

    @Override
    public XmlDiagnosticData build() {
        XmlDiagnosticData xmlDiagnosticData = super.build();
        if (attestationPresentation != null) {
            xmlDiagnosticData.setAttestationPresentationInfo(buildXmlAttestationPresentationInfo(attestationPresentation));
            List<Attestation> attestations = attestationPresentation.getAttestations();
            Collection<XmlAttestation> xmlAttestations = buildXmlAttestation(attestations);
            xmlDiagnosticData.getAttestations().addAll(xmlAttestations);

            if (Utils.isCollectionNotEmpty(attestationRevocationTokens)) {
                xmlDiagnosticData.getUsedAttestationRevocationTokens().addAll(buildXmlAttestationRevocationTokens(attestationRevocationTokens));
                linkAttestationAndRevocations(attestationPresentation.getAttestations());
            }
        }
        xmlDiagnosticData.setOrphanTokens(buildXmlOrphanTokens());
        return xmlDiagnosticData;
    }

    /**
     * Builds {@code XmlAttestationPresentationInfo} based on the {@code AttestationPresentation}
     *
     * @param attestationPresentation {@link AttestationPresentation}
     * @return {@link XmlAttestationPresentationInfo}
     */
    protected XmlAttestationPresentationInfo buildXmlAttestationPresentationInfo(AttestationPresentation attestationPresentation) {
        final XmlAttestationPresentationInfo xmlAttestationPresentationInfo = new XmlAttestationPresentationInfo();
        xmlAttestationPresentationInfo.setFormat(attestationPresentation.getDocumentFormat());
        if (Utils.isCollectionNotEmpty(attestationPresentation.getAttestations())) {
            for (Attestation attestation : attestationPresentation.getAttestations()) {
                xmlAttestationPresentationInfo.getDocuments().add(buildXmlAttestationDocument(attestation));
            }
        }
        return xmlAttestationPresentationInfo;
    }

    /**
     * Builds an instance of {@code XmlAttestationDocument} for a {@code Attestation}
     *
     * @param attestation {@link Attestation}
     * @return {@link XmlAttestationDocument}
     */
    protected XmlAttestationDocument buildXmlAttestationDocument(Attestation attestation) {
        final XmlAttestationDocument xmlAttestationDocument = new XmlAttestationDocument();
        xmlAttestationDocument.setAttestation(getXmlAttestation(attestation));
        return xmlAttestationDocument;
    }

    private Collection<XmlAttestation> buildXmlAttestation(Collection<Attestation> attestations) {
        List<XmlAttestation> builtAttestationPresentations = new ArrayList<>();
        for (Attestation attestation : attestations) {
            XmlAttestation xmlAttestationPresentation = getXmlAttestation(attestation);
            builtAttestationPresentations.add(xmlAttestationPresentation);
        }
        return builtAttestationPresentations;
    }

    private XmlAttestation getXmlAttestation(Attestation attestation) {
        return xmlAttestationMap.computeIfAbsent(attestation.getId(), k -> buildDetachedXmlAttestation(attestation));
    }

    /**
     * Builds an {@code XmlAttestation} instance
     *
     * @param attestation {@link Attestation}
     * @return {@link XmlAttestation}
     */
    protected XmlAttestation buildDetachedXmlAttestation(Attestation attestation) {
        final XmlAttestation xmlAttestationPresentation = new XmlAttestation();
        xmlAttestationPresentation.setId(identifierProvider.getIdAsString(attestation));
        xmlAttestationPresentation.setDocumentName(attestation.getFilename());
        xmlAttestationPresentation.setProfile(attestation.getAttestationProfile());
        for (AdvancedSignature signature : attestation.getSignatures()) {
            xmlAttestationPresentation.getAttestationSignature().add(getXmlAttestationSignature(signature));
        }
        xmlAttestationPresentation.setDigestMethod(attestation.getSelectiveDisclosuresDigestAlgorithm());
        xmlAttestationPresentation.setDigestMatchers(buildXmlDigestMatchers(attestation.getDisclosureValidations()));
        if (attestation.getKeyBindingSignature() != null) {
            xmlAttestationPresentation.setKeyBindingSignature(getXmlKeyBindingSignature(attestation.getKeyBindingSignature()));
        }
        xmlAttestationPresentation.setAttestationPayload(getXmlAttestationPayload(attestation.getPayload()));
        xmlAttestationPresentation.setKeyBindingPayload(getXmlKeyBindingPayload(attestation.getKeyBindingSignaturePayload()));
        return xmlAttestationPresentation;
    }

    private XmlAttestationSignature getXmlAttestationSignature(AdvancedSignature signature) {
        XmlAttestationSignature xmlAttestationPresentationSignature = new XmlAttestationSignature();
        XmlSignature xmlSignature = xmlSignaturesMap.get(signature.getId());
        if (xmlSignature == null) {
            throw new IllegalStateException(String.format(
                    "XmlSignature shall be built at this moment! Not found signature with id '%s'.", signature.getId()));
        }
        xmlAttestationPresentationSignature.setSignature(xmlSignature);
        return xmlAttestationPresentationSignature;
    }

    private XmlKeyBindingSignature getXmlKeyBindingSignature(AdvancedSignature signature) {
        XmlKeyBindingSignature xmlKeyBindingSignature = new XmlKeyBindingSignature();
        XmlSignature xmlSignature = xmlSignaturesMap.get(signature.getId());
        if (xmlSignature == null) {
            throw new IllegalStateException(String.format("XmlSignature for key binding shall be built at this moment! " +
                    "Not found signature with id '%s'.", signature.getId()));
        }
        xmlSignature.setKeyBindingSignature(signature.isKeyBindingSignature());
        xmlKeyBindingSignature.setSignature(xmlSignature);
        return xmlKeyBindingSignature;
    }

    private List<XmlDigestMatcher> buildXmlDigestMatchers(List<DisclosureValidation> disclosureValidations) {
        if (Utils.isCollectionEmpty(disclosureValidations)) {
            return Collections.emptyList();
        }
        final List<XmlDigestMatcher> result = new ArrayList<>();
        for (DisclosureValidation validation : disclosureValidations) {
            buildXmlDigestMatcherRecursively(validation, result);
        }
        return result;
    }

    private void buildXmlDigestMatcherRecursively(DisclosureValidation disclosureValidation, List<XmlDigestMatcher> digestMatchersList) {
        XmlDigestMatcher ref = getXmlDigestMatcher(disclosureValidation);
        digestMatchersList.add(ref);

        if (Utils.isCollectionNotEmpty(disclosureValidation.getDependentValidations())) {
            for (ReferenceValidation refValidation : disclosureValidation.getDependentValidations()) {
                if (!(refValidation instanceof DisclosureValidation)) {
                    throw new IllegalStateException("DisclosureValidation's dependent validations shall be of DisclosureValidation type!");
                }
                buildXmlDigestMatcherRecursively((DisclosureValidation) refValidation, digestMatchersList);
            }
        }
    }

    /**
     * Builds {@code XmlDigestMatcher} from the {@code DisclosureValidation}
     *
     * @param disclosureValidation {@link DisclosureValidation}
     * @return {@link XmlDigestMatcher}
     */
    protected XmlDigestMatcher getXmlDigestMatcher(DisclosureValidation disclosureValidation) {
        XmlDigestMatcher ref = new XmlDigestMatcher();
        ref.setType(disclosureValidation.getType());
        ref.setDisclosableClaim(getXmlDisclosableClaim(disclosureValidation));
        Digest digest = disclosureValidation.getDigest();
        if (digest != null) {
            ref.setDigestValue(digest.getValue());
            ref.setDigestMethod(digest.getAlgorithm());
        }
        ref.setDataFound(disclosureValidation.isFound());
        ref.setDataIntact(disclosureValidation.isIntact());
        return ref;
    }

    /**
     * Builds {@code XmlDisclosableClaim} from the {@code DisclosureValidation}
     *
     * @param disclosureValidation {@link DisclosureValidation}
     * @return {@link XmlDisclosableClaim}
     */
    protected XmlDisclosableClaim getXmlDisclosableClaim(DisclosureValidation disclosureValidation) {
        if (disclosureValidation == null || (disclosureValidation.getClaimName() == null && disclosureValidation.getValue() == null
                && disclosureValidation.getNamespace() == null && disclosureValidation.getDigestId() == null)) {
            return null;
        }
        XmlDisclosableClaim xmlClaim = new XmlDisclosableClaim();
        if (disclosureValidation.getDigestId() != null) {
            xmlClaim.setId(BigInteger.valueOf(disclosureValidation.getDigestId()));
        }
        xmlClaim.setName(disclosureValidation.getClaimName());
        xmlClaim.setNamespace(disclosureValidation.getNamespace());
        if (disclosureValidation.getValue() != null) {
            xmlClaim.setValue(disclosureValidation.getValue().getValueAsString());
        }
        return xmlClaim;
    }

    private XmlAttestationPayload getXmlAttestationPayload(AttestationPayload attestationPayload) {
        final List<XmlClaim> supportedClaims = new ArrayList<>();
        final XmlAttestationPayload xmlAttestationPayload = new XmlAttestationPayload();

        xmlAttestationPayload.setIdentifier(getXmlClaim(attestationPayload.getIdentifier(), supportedClaims));
        xmlAttestationPayload.setIssuer(getXmlClaim(attestationPayload.getIssuer(), supportedClaims));
        xmlAttestationPayload.setSubject(getXmlClaim(attestationPayload.getSubject(), supportedClaims));
        xmlAttestationPayload.setAudience(getXmlClaim(attestationPayload.getAudience(), supportedClaims));
        xmlAttestationPayload.setExpiration(getXmlClaim(attestationPayload.getExpirationTime(), supportedClaims));
        xmlAttestationPayload.setNotBefore(getXmlClaim(attestationPayload.getNotBeforeTime(), supportedClaims));
        xmlAttestationPayload.setIssuedAt(getXmlClaim(attestationPayload.getIssuedAtTime(), supportedClaims));
        xmlAttestationPayload.setUpdatedAt(getXmlClaim(attestationPayload.getUpdatedAtTime(), supportedClaims));
        xmlAttestationPayload.setCategory(getXmlClaim(attestationPayload.getCategory(), supportedClaims));
        xmlAttestationPayload.setVerifiableCredentialsType(getXmlVerifiableCredentialsType(attestationPayload, supportedClaims));
        xmlAttestationPayload.setStatus(getXmlStatus(attestationPayload.getStatus(), supportedClaims));
        xmlAttestationPayload.setNonce(getXmlClaim(attestationPayload.getNonce(), supportedClaims));
        xmlAttestationPayload.setDeviceKey(getXmlDeviceKeyClaim(attestationPayload.getDeviceKey(), supportedClaims));

        xmlAttestationPayload.setVersion(getXmlClaim(attestationPayload.getVersion(), supportedClaims));
        xmlAttestationPayload.setDocType(getXmlClaim(attestationPayload.getDocType(), supportedClaims));
        xmlAttestationPayload.setValidityInfo(getXmlValidityInfoClaim(attestationPayload.getValidityInfo(), supportedClaims));

        xmlAttestationPayload.setAdministrativeIssuanceDate(getXmlClaim(attestationPayload.getAdministrativeIssuanceDate(), supportedClaims));
        xmlAttestationPayload.setAdministrativeExpirationDate(getXmlClaim(attestationPayload.getAdministrativeExpirationDate(), supportedClaims));
        xmlAttestationPayload.setOneTimeUse(getXmlClaim(attestationPayload.getOneTimeUse(), supportedClaims));
        xmlAttestationPayload.setShortLived(getXmlClaim(attestationPayload.getShortLived(), supportedClaims));
        xmlAttestationPayload.setEvidence(getXmlClaim(attestationPayload.getEvidence(), supportedClaims));
        xmlAttestationPayload.setAttestedAttributesSubject(getXmlAttestedAttributesSubjectClaim(attestationPayload.getAttestedAttributesSubject(), supportedClaims)); // TODO : enhance with AttestedAttributesSubjectWrapper

        xmlAttestationPayload.setFullName(getXmlClaim(attestationPayload.getFullName(), supportedClaims));
        xmlAttestationPayload.setGivenName(getXmlClaim(attestationPayload.getGivenName(), supportedClaims));
        xmlAttestationPayload.setFamilyName(getXmlClaim(attestationPayload.getFamilyName(), supportedClaims));
        xmlAttestationPayload.setMiddleName(getXmlClaim(attestationPayload.getMiddleName(), supportedClaims));
        xmlAttestationPayload.setNickname(getXmlClaim(attestationPayload.getNickname(), supportedClaims));
        xmlAttestationPayload.setShortName(getXmlClaim(attestationPayload.getShortName(), supportedClaims));
        xmlAttestationPayload.setProfileUrl(getXmlClaim(attestationPayload.getProfileUrl(), supportedClaims));
        xmlAttestationPayload.setPictureUrl(getXmlClaim(attestationPayload.getPictureUrl(), supportedClaims));
        xmlAttestationPayload.setWebsiteUrl(getXmlClaim(attestationPayload.getWebsiteUrl(), supportedClaims));
        xmlAttestationPayload.setEmail(getXmlClaim(attestationPayload.getEmail(), supportedClaims));
        xmlAttestationPayload.setEmailVerified(getXmlClaim(attestationPayload.getEmailVerified(), supportedClaims));
        xmlAttestationPayload.setGender(getXmlClaim(attestationPayload.getGender(), supportedClaims));
        xmlAttestationPayload.setBirthdate(getXmlBirthdateClaim(attestationPayload.getBirthdate(), supportedClaims));
        xmlAttestationPayload.setTimezone(getXmlClaim(attestationPayload.getTimezone(), supportedClaims));
        xmlAttestationPayload.setLocale(getXmlClaim(attestationPayload.getLocale(), supportedClaims));
        xmlAttestationPayload.setAddress(getXmlAddressClaim(attestationPayload.getAddress(), supportedClaims));
        xmlAttestationPayload.setPhoneNumber(getXmlClaim(attestationPayload.getPhoneNumber(), supportedClaims));
        xmlAttestationPayload.setPhoneNumberVerified(getXmlClaim(attestationPayload.getPhoneNumberVerified(), supportedClaims));
        xmlAttestationPayload.setPlaceOfBirth(getXmlPlaceOfBirthClaim(attestationPayload.getPlaceOfBirth(), supportedClaims));
        xmlAttestationPayload.setNationalities(getXmlClaim(attestationPayload.getNationalities(), supportedClaims));
        xmlAttestationPayload.setBirthFamilyName(getXmlClaim(attestationPayload.getBirthFamilyName(), supportedClaims));
        xmlAttestationPayload.setBirthGivenName(getXmlClaim(attestationPayload.getBirthGivenName(), supportedClaims));
        xmlAttestationPayload.setBirthMiddleName(getXmlClaim(attestationPayload.getBirthMiddleName(), supportedClaims));
        xmlAttestationPayload.setSalutation(getXmlClaim(attestationPayload.getSalutation(), supportedClaims));
        xmlAttestationPayload.setTitle(getXmlClaim(attestationPayload.getTitle(), supportedClaims));
        xmlAttestationPayload.setMobilePhoneNumber(getXmlClaim(attestationPayload.getMobilePhoneNumber(), supportedClaims));
        xmlAttestationPayload.setPseudonym(getXmlClaim(attestationPayload.getPseudonym(), supportedClaims));
        xmlAttestationPayload.getCredentialSubject().addAll(getXmlCredentialSubjectClaimList(attestationPayload.getCredentialSubjects(), supportedClaims));

        xmlAttestationPayload.setIssuingCountry(getXmlClaim(attestationPayload.getIssuingCountry(), supportedClaims));
        xmlAttestationPayload.setIssuingAuthority(getXmlClaim(attestationPayload.getIssuingAuthority(), supportedClaims));
        xmlAttestationPayload.setDocumentNumber(getXmlClaim(attestationPayload.getDocumentNumber(), supportedClaims));
        xmlAttestationPayload.setPortrait(getXmlClaim(attestationPayload.getPortrait(), supportedClaims));
        xmlAttestationPayload.setDrivingPrivileges(getXmlDrivingPrivilegesClaim(attestationPayload.getDrivingPrivileges(), supportedClaims));
        xmlAttestationPayload.setUNDistinguishingSign(getXmlClaim(attestationPayload.getUNDistinguishingSign(), supportedClaims));
        xmlAttestationPayload.setPersonalAdministrativeNumber(getXmlClaim(attestationPayload.getPersonalAdministrativeNumber(), supportedClaims));
        xmlAttestationPayload.setHeight(getXmlClaim(attestationPayload.getHeight(), supportedClaims));
        xmlAttestationPayload.setWeight(getXmlClaim(attestationPayload.getWeight(), supportedClaims));
        xmlAttestationPayload.setEyeColour(getXmlClaim(attestationPayload.getEyeColour(), supportedClaims));
        xmlAttestationPayload.setHairColour(getXmlClaim(attestationPayload.getHairColour(), supportedClaims));
        xmlAttestationPayload.setResidentPostalAddress(getXmlClaim(attestationPayload.getPostalAddress(), supportedClaims));
        xmlAttestationPayload.setPortraitCaptureDate(getXmlClaim(attestationPayload.getPortraitCaptureDate(), supportedClaims));
        xmlAttestationPayload.setAgeInYears(getXmlClaim(attestationPayload.getAgeInYears(), supportedClaims));
        xmlAttestationPayload.setAgeBirthYear(getXmlClaim(attestationPayload.getAgeBirthYear(), supportedClaims));
        xmlAttestationPayload.setAgeEqualOrOver(getXmlAgeEqualOrOverClaim(attestationPayload.getAgeEqualOrOver(), supportedClaims));
        xmlAttestationPayload.getAgeOverNN().addAll(getXmlAgeOverNNClaims(attestationPayload.getAgeOverNN(), supportedClaims));
        xmlAttestationPayload.setIssuingJurisdiction(getXmlClaim(attestationPayload.getIssuingJurisdiction(), supportedClaims));
        xmlAttestationPayload.setResidentAddressCity(getXmlClaim(attestationPayload.getResidentAddressCity(), supportedClaims));
        xmlAttestationPayload.setResidentAddressState(getXmlClaim(attestationPayload.getResidentAddressState(), supportedClaims));
        xmlAttestationPayload.setResidentAddressPostalCode(getXmlClaim(attestationPayload.getResidentAddressPostalCode(), supportedClaims));
        xmlAttestationPayload.setResidentAddressCountry(getXmlClaim(attestationPayload.getResidentAddressCountry(), supportedClaims));
        xmlAttestationPayload.getBiometricTemplate().addAll(getXmlBiometricTemplateXXClaim(attestationPayload.getBiometricTemplate(), supportedClaims));
        xmlAttestationPayload.setSignatureUsualMark(getXmlClaim(attestationPayload.getSignatureUsualMark(), supportedClaims));
        xmlAttestationPayload.setFingerprint(getXmlClaim(attestationPayload.getFingerprint(), supportedClaims));
        xmlAttestationPayload.setBusinessName(getXmlClaim(attestationPayload.getBusinessName(), supportedClaims));
        xmlAttestationPayload.setOrganizationName(getXmlClaim(attestationPayload.getOrganizationName(), supportedClaims));
        xmlAttestationPayload.setBirthFullName(getXmlClaim(attestationPayload.getBirthFullName(), supportedClaims));
        xmlAttestationPayload.setProfession(getXmlClaim(attestationPayload.getProfession(), supportedClaims));
        xmlAttestationPayload.setRelationshipFather(getXmlClaim(attestationPayload.getRelationshipFather(), supportedClaims));
        xmlAttestationPayload.setRelationshipMother(getXmlClaim(attestationPayload.getRelationshipMother(), supportedClaims));
        xmlAttestationPayload.setRelationshipParent(getXmlClaim(attestationPayload.getRelationshipParent(), supportedClaims));
        xmlAttestationPayload.setRelationshipSon(getXmlClaim(attestationPayload.getRelationshipSon(), supportedClaims));
        xmlAttestationPayload.setRelationshipDaughter(getXmlClaim(attestationPayload.getRelationshipDaughter(), supportedClaims));
        xmlAttestationPayload.setRelationshipBrother(getXmlClaim(attestationPayload.getRelationshipBrother(), supportedClaims));
        xmlAttestationPayload.setRelationshipSister(getXmlClaim(attestationPayload.getRelationshipSister(), supportedClaims));
        xmlAttestationPayload.setRelationshipSibling(getXmlClaim(attestationPayload.getRelationshipSibling(), supportedClaims));
        xmlAttestationPayload.setRelationshipSpouse(getXmlClaim(attestationPayload.getRelationshipSpouse(), supportedClaims));
        xmlAttestationPayload.setRelationshipFatherInLaw(getXmlClaim(attestationPayload.getRelationshipFatherInLaw(), supportedClaims));
        xmlAttestationPayload.setRelationshipMotherInLaw(getXmlClaim(attestationPayload.getRelationshipMotherInLaw(), supportedClaims));
        xmlAttestationPayload.setRelationshipParentInLaw(getXmlClaim(attestationPayload.getRelationshipParentInLaw(), supportedClaims));
        xmlAttestationPayload.setRelationshipSonInLaw(getXmlClaim(attestationPayload.getRelationshipSonInLaw(), supportedClaims));
        xmlAttestationPayload.setRelationshipDaughterInLaw(getXmlClaim(attestationPayload.getRelationshipDaughterInLaw(), supportedClaims));
        xmlAttestationPayload.setRelationshipChildInLaw(getXmlClaim(attestationPayload.getRelationshipChildInLaw(), supportedClaims));
        xmlAttestationPayload.setRelationshipParentalAuthority(getXmlClaim(attestationPayload.getRelationshipParentalAuthority(), supportedClaims));
        xmlAttestationPayload.setRelationshipLegalRepresentative(getXmlClaim(attestationPayload.getRelationshipLegalRepresentative(), supportedClaims));
        xmlAttestationPayload.setRelationshipAgent(getXmlClaim(attestationPayload.getRelationshipAgent(), supportedClaims));
        xmlAttestationPayload.setDocumentType(getXmlClaim(attestationPayload.getDocumentType(), supportedClaims));

        xmlAttestationPayload.setIssuingAuthorityRegistrationIdentifier(getXmlClaim(attestationPayload.getIssuingAuthorityRegistrationIdentifier(), supportedClaims));
        xmlAttestationPayload.setTrustAnchor(getXmlClaim(attestationPayload.getTrustAnchor(), supportedClaims));
        xmlAttestationPayload.setResidentAddressStreet(getXmlClaim(attestationPayload.getResidentAddressStreet(), supportedClaims));
        xmlAttestationPayload.setResidentAddressHouseNumber(getXmlClaim(attestationPayload.getResidentAddressHouseNumber(), supportedClaims));

        xmlAttestationPayload.getOtherClaim().addAll(getOtherClaims(attestationPayload, supportedClaims));

        return xmlAttestationPayload;
    }

    private XmlKeyBindingPayload getXmlKeyBindingPayload(KeyBindingSignaturePayload keyBindingPayload) {
        if (keyBindingPayload == null) {
            return null;
        }

        final List<XmlClaim> supportedClaims = new ArrayList<>();
        final XmlKeyBindingPayload xmlKeyBindingPayload = new XmlKeyBindingPayload();

        xmlKeyBindingPayload.setNonce(getXmlClaim(keyBindingPayload.getNonce(), supportedClaims));
        xmlKeyBindingPayload.setAudience(getXmlClaim(keyBindingPayload.getAudience(), supportedClaims));
        xmlKeyBindingPayload.setIssuanceTime(getXmlClaim(keyBindingPayload.getIssuedAt(), supportedClaims));

        xmlKeyBindingPayload.getOtherClaim().addAll(getOtherClaims(keyBindingPayload, supportedClaims));
        return xmlKeyBindingPayload;
    }

    private XmlClaim getXmlClaim(VerifiedClaim claim) {
        return getXmlClaim(claim, (List<XmlClaim>) null);
    }

    private XmlClaim getXmlClaim(VerifiedClaim claim, List<XmlClaim> supportedClaims) {
        return getXmlClaim(claim, new XmlClaim(), supportedClaims);
    }

    private <T extends XmlClaim> T getXmlClaim(VerifiedClaim claim, T xmlClaim) {
        return getXmlClaim(claim, xmlClaim, null);
    }

    private <T extends XmlClaim> T getXmlClaim(VerifiedClaim claim, T xmlClaim, List<XmlClaim> supportedClaims) {
        if (claim != null) {
            appendGenericInfo(xmlClaim, claim, supportedClaims);
            if (claim.isStringValueType()) {
                xmlClaim.setText(claim.getStringValue());
            } else if (claim.isNumberValueType()) {
                xmlClaim.setNumber(BigInteger.valueOf(claim.getNumberValue().longValue()));
            } else if (claim.isDateValueType()) {
                xmlClaim.setDateTime(claim.getDateValue());
            } else if (claim.isBooleanValueType()) {
                xmlClaim.setBoolean(claim.getBooleanValue());
            } else if (claim.isBinaryValueType()) {
                xmlClaim.setBinary(claim.getBinaryValue());
            } else if (claim.isArrayValueType()) {
                for (VerifiedClaim claimItem : claim.getListValue()) {
                    xmlClaim.getItem().add(getXmlClaim(claimItem, new XmlClaim()));
                }
            } else if (claim.isMapValueType()) {
                for (Map.Entry<String, VerifiedClaim> entry : claim.getMapValue().entrySet()) {
                    xmlClaim.getEntry().add(getXmlClaim(entry.getValue(), new XmlClaim()));
                }
            } else if (claim.isNullValueType()) {
                // no information is to be embedded
            } else {
                throw new UnsupportedOperationException(String.format("Unsupported Claim type '%s'", claim.getClass().getSimpleName()));
            }
            return xmlClaim;
        }
        return null;
    }

    private XmlVerifiableCredentialsTypeClaim getXmlVerifiableCredentialsType(AttestationPayload attestationPayload, List<XmlClaim> supportedClaims) {
        VerifiedClaimString metadata = attestationPayload.getVerifiableCredentialsType();
        if (metadata != null) {
            XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsType = getXmlClaim(metadata, new XmlVerifiableCredentialsTypeClaim(), supportedClaims);
            if (attestationPayload.getVerifiableCredentialsTypeIntegrity() != null) {
                xmlVerifiableCredentialsType.setIntegrity(getXmlIntegrityClaim(attestationPayload.getVerifiableCredentialsTypeIntegrity(), supportedClaims));
            }
            return xmlVerifiableCredentialsType;
        }
        return null;
    }

    private XmlStatusClaim getXmlStatus(VerifiedClaimStatus claimStatus, List<XmlClaim> supportedClaims) {
        if (claimStatus == null) {
            return null;
        }
        XmlStatusClaim xmlStatus = new XmlStatusClaim();
        appendGenericInfo(xmlStatus, claimStatus, supportedClaims);

        List<XmlClaim> claimSupportedClaims = new ArrayList<>();
        if (claimStatus.getStatusList() != null) {
            xmlStatus.setStatusList(getXmlStatusList(claimStatus.getStatusList(), claimSupportedClaims));
        }
        if (claimStatus.getIdentifierList() != null) {
            xmlStatus.setIdentifierList(getXmlIdentifierList(claimStatus.getIdentifierList(), claimSupportedClaims));
        }
        if (claimStatus.getIndex() != null) {
            xmlStatus.setIndex(getXmlClaim(claimStatus.getIndex(), claimSupportedClaims));
        }
        if (claimStatus.getUri() != null) {
            xmlStatus.setUri(getXmlClaim(claimStatus.getUri(), claimSupportedClaims));
        }
        if (claimStatus.getType() != null) {
            xmlStatus.setType(getXmlClaim(claimStatus.getType(), claimSupportedClaims));
        }
        if (claimStatus.getPurpose() != null) {
            xmlStatus.setPurpose(getXmlClaim(claimStatus.getPurpose(), claimSupportedClaims));
        }
        xmlStatus.getEntry().addAll(getOtherClaims(claimStatus, claimSupportedClaims));
        return xmlStatus;
    }

    private XmlStatusListClaim getXmlStatusList(VerifiedClaimStatusList claimStatusList, List<XmlClaim> supportedClaims) {
        if (claimStatusList == null) {
            return null;
        }
        XmlStatusListClaim xmlStatusList = new XmlStatusListClaim();
        appendGenericInfo(xmlStatusList, claimStatusList, supportedClaims);

        List<XmlClaim> claimSupportedClaims = new ArrayList<>();
        if (claimStatusList.getIndex() != null) {
            xmlStatusList.setIndex(getXmlClaim(claimStatusList.getIndex(), claimSupportedClaims));
        }
        if (claimStatusList.getUri() != null) {
            xmlStatusList.setUri(getXmlClaim(claimStatusList.getUri(), claimSupportedClaims));
        }
        if (claimStatusList.getCertificate() != null) {
            xmlStatusList.setCertificate(getXmlClaim(claimStatusList.getCertificate(), claimSupportedClaims));
        }
        xmlStatusList.getEntry().addAll(getOtherClaims(claimStatusList, claimSupportedClaims));
        return xmlStatusList;
    }

    private XmlIdentifierListClaim getXmlIdentifierList(VerifiedClaimIdentifierList claimStatusList, List<XmlClaim> supportedClaims) {
        if (claimStatusList == null) {
            return null;
        }
        XmlIdentifierListClaim xmlIdentifierList = new XmlIdentifierListClaim();
        appendGenericInfo(xmlIdentifierList, claimStatusList, supportedClaims);

        List<XmlClaim> claimSupportedClaims = new ArrayList<>();
        if (claimStatusList.getIdentifier() != null) {
            xmlIdentifierList.setIdentifier(getXmlClaim(claimStatusList.getIdentifier(), claimSupportedClaims));
        }
        if (claimStatusList.getUri() != null) {
            xmlIdentifierList.setUri(getXmlClaim(claimStatusList.getUri(), claimSupportedClaims));
        }
        if (claimStatusList.getCertificate() != null) {
            xmlIdentifierList.setCertificate(getXmlClaim(claimStatusList.getCertificate(), claimSupportedClaims));
        }
        xmlIdentifierList.getEntry().addAll(getOtherClaims(claimStatusList, claimSupportedClaims));
        return xmlIdentifierList;
    }

    private XmlDeviceKeyClaim getXmlDeviceKeyClaim(VerifiedClaimDeviceKey deviceKey, List<XmlClaim> supportedClaims) {
        if (deviceKey == null) {
            return null;
        }
        // NOTE: here we aim to preserve the original structure of the claim
        XmlDeviceKeyClaim xmlDeviceKeyClaim = getXmlClaim(deviceKey, new XmlDeviceKeyClaim(), supportedClaims);
        if (deviceKey.getPublicKey() != null) {
            xmlDeviceKeyClaim.setPublicKey(deviceKey.getPublicKey().getEncoded());
        }
        List<CertificateToken> certificates = deviceKey.getCertificates();
        if (Utils.isCollectionNotEmpty(certificates)) {
            for (CertificateToken certificateToken : certificates) {
                XmlX509Certificate xmlX509Certificate = new XmlX509Certificate();
                xmlX509Certificate.setCertificate(xmlCertsMap.get(certificateToken.getDSSIdAsString()));
                xmlDeviceKeyClaim.getX509Certificate().add(xmlX509Certificate);
            }
        }
        List<Digest> certificateDigests = deviceKey.getCertificateDigests();
        if (Utils.isCollectionNotEmpty(certificateDigests)) {
            for (Digest digest : certificateDigests) {
                xmlDeviceKeyClaim.getDigestAlgoAndValue().add(getXmlDigestAlgoAndValue(digest));
            }
        }
        List<String> certificateKeyIdentifiers = deviceKey.getCertificateKeyIdentifiers();
        if (Utils.isCollectionNotEmpty(certificateKeyIdentifiers)) {
            for (String kid : certificateKeyIdentifiers) {
                xmlDeviceKeyClaim.getKID().add(kid);
            }
        }
        List<String> certificateUrls = deviceKey.getCertificateUrls();
        if (Utils.isCollectionNotEmpty(certificateUrls)) {
            for (String url : certificateUrls) {
                xmlDeviceKeyClaim.getX509Url().add(url);
            }
        }
        xmlDeviceKeyClaim.setKeyAuthorizations(getXmlKeyAuthorizations(deviceKey.getAuthorizedNamespaces(), deviceKey.getAuthorizedDataElements()));
        return xmlDeviceKeyClaim;
    }

    private XmlKeyAuthorizations getXmlKeyAuthorizations(List<String> authorizedNamespaces, Map<String, List<String>> authorizedDataElements) {
        if (Utils.isCollectionEmpty(authorizedNamespaces) && Utils.isMapEmpty(authorizedDataElements)) {
            return null;
        }

        final XmlKeyAuthorizations xmlKeyAuthorizations = new XmlKeyAuthorizations();
        if (Utils.isCollectionNotEmpty(authorizedNamespaces)) {
            xmlKeyAuthorizations.getAuthorizedNamespace().addAll(authorizedNamespaces);
        }
        if (Utils.isMapNotEmpty(authorizedDataElements)) {
            authorizedDataElements.forEach((k, v) -> xmlKeyAuthorizations.getAuthorizedDataElements().add(getXmlAuthorizedDataElements(k, v)));
        }
        return xmlKeyAuthorizations;
    }

    private XmlAuthorizedDataElements getXmlAuthorizedDataElements(String namespace, List<String> dataElements) {
        XmlAuthorizedDataElements xmlAuthorizedDataElement = new XmlAuthorizedDataElements();
        xmlAuthorizedDataElement.setNamespace(namespace);
        xmlAuthorizedDataElement.getDataElement().addAll(dataElements);
        return xmlAuthorizedDataElement;
    }

    private XmlValidityInfoClaim getXmlValidityInfoClaim(VerifiedClaimValidityInfo validityInfo, List<XmlClaim> supportedClaims) {
        if (validityInfo == null) {
            return null;
        }
        XmlValidityInfoClaim xmlValidityInfoClaim = new XmlValidityInfoClaim();
        appendGenericInfo(xmlValidityInfoClaim, validityInfo, supportedClaims);

        List<XmlClaim> claimSupportedClaims = new ArrayList<>();
        if (validityInfo.getSigned() != null) {
            xmlValidityInfoClaim.setSigned(getXmlClaim(validityInfo.getSigned(), claimSupportedClaims));
        }
        if (validityInfo.getValidFrom() != null) {
            xmlValidityInfoClaim.setValidFrom(getXmlClaim(validityInfo.getValidFrom(), claimSupportedClaims));
        }
        if (validityInfo.getValidUntil() != null) {
            xmlValidityInfoClaim.setValidUntil(getXmlClaim(validityInfo.getValidUntil(), claimSupportedClaims));
        }
        if (validityInfo.getExpectedUpdate() != null) {
            xmlValidityInfoClaim.setExpectedUpdate(getXmlClaim(validityInfo.getExpectedUpdate(), claimSupportedClaims));
        }
        xmlValidityInfoClaim.getEntry().addAll(getOtherClaims(validityInfo, claimSupportedClaims));
        return xmlValidityInfoClaim;
    }

    private XmlAddressClaim getXmlAddressClaim(VerifiedClaimAddress claimAddress, List<XmlClaim> supportedClaims) {
        if (claimAddress == null) {
            return null;
        }
        XmlAddressClaim xmlAddress = new XmlAddressClaim();
        appendGenericInfo(xmlAddress, claimAddress, supportedClaims);

        List<XmlClaim> claimSupportedClaims = new ArrayList<>();
        if (claimAddress.getPostalAddress() != null) {
            xmlAddress.setPostalAddress(getXmlClaim(claimAddress.getPostalAddress(), claimSupportedClaims));
        }
        if (claimAddress.getStreetAddress() != null) {
            xmlAddress.setStreetAddress(getXmlClaim(claimAddress.getStreetAddress(), claimSupportedClaims));
        }
        if (claimAddress.getCity() != null) {
            xmlAddress.setCity(getXmlClaim(claimAddress.getCity(), claimSupportedClaims));
        }
        if (claimAddress.getStateOrProvince() != null) {
            xmlAddress.setStateOrProvince(getXmlClaim(claimAddress.getStateOrProvince(), claimSupportedClaims));
        }
        if (claimAddress.getPostalCode() != null) {
            xmlAddress.setPostalCode(getXmlClaim(claimAddress.getPostalCode(), claimSupportedClaims));
        }
        if (claimAddress.getCountry() != null) {
            xmlAddress.setCountryName(getXmlClaim(claimAddress.getCountry(), claimSupportedClaims));
        }
        xmlAddress.getEntry().addAll(getOtherClaims(claimAddress, claimSupportedClaims));
        return xmlAddress;
    }

    private XmlBirthdateClaim getXmlBirthdateClaim(VerifiedClaim claim, List<XmlClaim> supportedClaims) {
        if (claim == null) {
            return null;
        }
        if (claim instanceof VerifiedClaimBirthDate) {
            VerifiedClaimBirthDate claimBirthDate = (VerifiedClaimBirthDate) claim;
            XmlBirthdateClaim xmlBirthdateClaim = new XmlBirthdateClaim();
            appendGenericInfo(xmlBirthdateClaim, claimBirthDate, supportedClaims);

            List<XmlClaim> claimSupportedClaims = new ArrayList<>();
            if (claimBirthDate.getBirthDate() != null) {
                xmlBirthdateClaim.setBirthdate(getXmlClaim(claimBirthDate.getBirthDate(), claimSupportedClaims));
            }
            if (claimBirthDate.getApproximateMask() != null) {
                xmlBirthdateClaim.setApproximateMask(getXmlClaim(claimBirthDate.getApproximateMask(), claimSupportedClaims));
            }
            xmlBirthdateClaim.getEntry().addAll(getOtherClaims(claimBirthDate, claimSupportedClaims));
            return xmlBirthdateClaim;
        }
        return getXmlClaim(claim, new XmlBirthdateClaim(), supportedClaims);
    }

    private XmlPlaceOfBirthClaim getXmlPlaceOfBirthClaim(VerifiedClaim claim, List<XmlClaim> supportedClaims) {
        if (claim == null) {
            return null;
        }
        if (claim instanceof VerifiedClaimPlaceOfBirth) {
            VerifiedClaimPlaceOfBirth claimPlaceOfBirth = (VerifiedClaimPlaceOfBirth) claim;
            XmlPlaceOfBirthClaim xmlPlaceOfBirthClaim = new XmlPlaceOfBirthClaim();
            appendGenericInfo(xmlPlaceOfBirthClaim, claimPlaceOfBirth, supportedClaims);

            List<XmlClaim> claimSupportedClaims = new ArrayList<>();
            if (claimPlaceOfBirth.getCountry() != null) {
                xmlPlaceOfBirthClaim.setCountry(getXmlClaim(claimPlaceOfBirth.getCountry(), claimSupportedClaims));
            }
            if (claimPlaceOfBirth.getStateOrProvince() != null) {
                xmlPlaceOfBirthClaim.setRegion(getXmlClaim(claimPlaceOfBirth.getStateOrProvince(), claimSupportedClaims));
            }
            if (claimPlaceOfBirth.getCity() != null) {
                xmlPlaceOfBirthClaim.setCity(getXmlClaim(claimPlaceOfBirth.getCity(), claimSupportedClaims));
            }
            xmlPlaceOfBirthClaim.getEntry().addAll(getOtherClaims(claimPlaceOfBirth, claimSupportedClaims));
            return xmlPlaceOfBirthClaim;

        }
        return getXmlClaim(claim, new XmlPlaceOfBirthClaim(), supportedClaims);
    }

    private XmlIntegrityClaim getXmlIntegrityClaim(VerifiedClaimIntegrity claimIntegrity, List<XmlClaim> supportedClaims) {
        if (claimIntegrity == null) {
            return null;
        }
        XmlIntegrityClaim xmlIntegrityClaim = getXmlClaim(claimIntegrity, new XmlIntegrityClaim(), supportedClaims);
        if (claimIntegrity.getDigestAlgorithm() != null) {
            xmlIntegrityClaim.setDigestMethod(claimIntegrity.getDigestAlgorithm());
        }
        if (claimIntegrity.getDigestValue() != null) {
            xmlIntegrityClaim.setDigestValue(claimIntegrity.getDigestValue());
        }
        return xmlIntegrityClaim;
    }

    private List<XmlCredentialSubjectClaim> getXmlCredentialSubjectClaimList(List<VerifiedClaimCredentialSubject> credentialSubjects, List<XmlClaim> supportedClaims) {
        if (Utils.isCollectionEmpty(credentialSubjects)) {
            return Collections.emptyList();
        }
        return credentialSubjects.stream().map(s -> getXmlCredentialSubjectClaim(s, supportedClaims)).collect(Collectors.toList());
    }

    private XmlCredentialSubjectClaim getXmlCredentialSubjectClaim(VerifiedClaimCredentialSubject credentialSubject, List<XmlClaim> supportedClaims) {
        XmlCredentialSubjectClaim xmlCredentialSubjectClaim = new XmlCredentialSubjectClaim();
        appendGenericInfo(xmlCredentialSubjectClaim, credentialSubject, supportedClaims);
        xmlCredentialSubjectClaim.setFullName(getXmlClaim(credentialSubject.getFullName(), supportedClaims));
        xmlCredentialSubjectClaim.setGivenName(getXmlClaim(credentialSubject.getGivenName(), supportedClaims));
        xmlCredentialSubjectClaim.setFamilyName(getXmlClaim(credentialSubject.getFamilyName(), supportedClaims));
        xmlCredentialSubjectClaim.setMiddleName(getXmlClaim(credentialSubject.getMiddleName(), supportedClaims));
        xmlCredentialSubjectClaim.setNickname(getXmlClaim(credentialSubject.getNickname(), supportedClaims));
        xmlCredentialSubjectClaim.setShortName(getXmlClaim(credentialSubject.getShortName(), supportedClaims));
        xmlCredentialSubjectClaim.setProfileUrl(getXmlClaim(credentialSubject.getProfileUrl(), supportedClaims));
        xmlCredentialSubjectClaim.setPictureUrl(getXmlClaim(credentialSubject.getPictureUrl(), supportedClaims));
        xmlCredentialSubjectClaim.setWebsiteUrl(getXmlClaim(credentialSubject.getWebsiteUrl(), supportedClaims));
        xmlCredentialSubjectClaim.setEmail(getXmlClaim(credentialSubject.getEmail(), supportedClaims));
        xmlCredentialSubjectClaim.setEmailVerified(getXmlClaim(credentialSubject.getEmailVerified(), supportedClaims));
        xmlCredentialSubjectClaim.setGender(getXmlClaim(credentialSubject.getGender(), supportedClaims));
        xmlCredentialSubjectClaim.setBirthdate(getXmlBirthdateClaim(credentialSubject.getBirthdate(), supportedClaims));
        xmlCredentialSubjectClaim.setTimezone(getXmlClaim(credentialSubject.getTimezone(), supportedClaims));
        xmlCredentialSubjectClaim.setLocale(getXmlClaim(credentialSubject.getLocale(), supportedClaims));
        xmlCredentialSubjectClaim.setAddress(getXmlAddressClaim(credentialSubject.getAddress(), supportedClaims));
        xmlCredentialSubjectClaim.setPhoneNumber(getXmlClaim(credentialSubject.getPhoneNumber(), supportedClaims));
        xmlCredentialSubjectClaim.setPhoneNumberVerified(getXmlClaim(credentialSubject.getPhoneNumberVerified(), supportedClaims));
        xmlCredentialSubjectClaim.setPlaceOfBirth(getXmlPlaceOfBirthClaim(credentialSubject.getPlaceOfBirth(), supportedClaims));
        xmlCredentialSubjectClaim.setNationalities(getXmlClaim(credentialSubject.getNationalities(), supportedClaims));
        xmlCredentialSubjectClaim.setBirthFamilyName(getXmlClaim(credentialSubject.getBirthFamilyName(), supportedClaims));
        xmlCredentialSubjectClaim.setBirthGivenName(getXmlClaim(credentialSubject.getBirthGivenName(), supportedClaims));
        xmlCredentialSubjectClaim.setBirthMiddleName(getXmlClaim(credentialSubject.getBirthMiddleName(), supportedClaims));
        xmlCredentialSubjectClaim.setSalutation(getXmlClaim(credentialSubject.getSalutation(), supportedClaims));
        xmlCredentialSubjectClaim.setTitle(getXmlClaim(credentialSubject.getTitle(), supportedClaims));
        xmlCredentialSubjectClaim.setMobilePhoneNumber(getXmlClaim(credentialSubject.getMobilePhoneNumber(), supportedClaims));
        xmlCredentialSubjectClaim.setPseudonym(getXmlClaim(credentialSubject.getPseudonym(), supportedClaims));

        xmlCredentialSubjectClaim.getOtherClaim().addAll(getOtherClaims(credentialSubject, supportedClaims));
        return xmlCredentialSubjectClaim;
    }

    private XmlDrivingPrivilegesClaim getXmlDrivingPrivilegesClaim(VerifiedClaimDrivingPrivileges claimDrivingPrivileges, List<XmlClaim> supportedClaims) {
        if (claimDrivingPrivileges == null) {
            return null;
        }
        XmlDrivingPrivilegesClaim xmlDrivingPrivilegesClaim = new XmlDrivingPrivilegesClaim();
        appendGenericInfo(xmlDrivingPrivilegesClaim, claimDrivingPrivileges, supportedClaims);
        if (Utils.isCollectionNotEmpty(claimDrivingPrivileges.getListValue())) {
            for (VerifiedClaim claimDrivingPrivilege : claimDrivingPrivileges.getListValue()) {
                if (claimDrivingPrivilege instanceof VerifiedClaimDrivingPrivilege) {
                    XmlDrivingPrivilegeClaim xmlDrivingPrivilegeClaim = getXmlDrivingPrivilegeClaim((VerifiedClaimDrivingPrivilege) claimDrivingPrivilege);
                    if (xmlDrivingPrivilegeClaim != null) {
                        xmlDrivingPrivilegesClaim.getDrivingPrivilege().add(xmlDrivingPrivilegeClaim);
                    }
                } else {
                    xmlDrivingPrivilegesClaim.getItem().add(getXmlClaim(claimDrivingPrivilege, supportedClaims));
                }
            }
        }
        return xmlDrivingPrivilegesClaim;
    }

    private XmlDrivingPrivilegeClaim getXmlDrivingPrivilegeClaim(VerifiedClaimDrivingPrivilege claimDrivingPrivilege) {
        if (claimDrivingPrivilege == null) {
            return null;
        }
        XmlDrivingPrivilegeClaim xmlDrivingPrivilegeClaim = new XmlDrivingPrivilegeClaim();
        appendGenericInfo(xmlDrivingPrivilegeClaim, claimDrivingPrivilege);

        List<XmlClaim> claimSupportedClaims = new ArrayList<>();
        if (claimDrivingPrivilege.getVehicleCategoryCode() != null) {
            xmlDrivingPrivilegeClaim.setVehicleCategoryCode(getXmlClaim(claimDrivingPrivilege.getVehicleCategoryCode(), claimSupportedClaims));
        }
        if (claimDrivingPrivilege.getIssueDate() != null) {
            xmlDrivingPrivilegeClaim.setIssueDate(getXmlClaim(claimDrivingPrivilege.getIssueDate(), claimSupportedClaims));
        }
        if (claimDrivingPrivilege.getExpiryDate() != null) {
            xmlDrivingPrivilegeClaim.setExpiryDate(getXmlClaim(claimDrivingPrivilege.getExpiryDate(), claimSupportedClaims));
        }
        if (claimDrivingPrivilege.getCodes() != null) {
            xmlDrivingPrivilegeClaim.setCodes(getXmlDrivingPrivilegeCodesClaim(claimDrivingPrivilege.getCodes(), claimSupportedClaims));
        }
        xmlDrivingPrivilegeClaim.getEntry().addAll(getOtherClaims(claimDrivingPrivilege, claimSupportedClaims));
        return xmlDrivingPrivilegeClaim;
    }

    private XmlDrivingPrivilegeCodesClaim getXmlDrivingPrivilegeCodesClaim(VerifiedClaimDrivingPrivilegeCodes claimDrivingPrivilegeCodes, List<XmlClaim> supportedClaims) {
        if (claimDrivingPrivilegeCodes == null) {
            return null;
        }
        XmlDrivingPrivilegeCodesClaim xmlDrivingPrivilegeCodesClaim = new XmlDrivingPrivilegeCodesClaim();
        appendGenericInfo(xmlDrivingPrivilegeCodesClaim, claimDrivingPrivilegeCodes, supportedClaims);
        if (Utils.isCollectionNotEmpty(claimDrivingPrivilegeCodes.getListValue())) {
            for (VerifiedClaim claimDrivingPrivilegeCode : claimDrivingPrivilegeCodes.getListValue()) {
                if (claimDrivingPrivilegeCode instanceof VerifiedClaimDrivingPrivilegeCode) {
                    XmlDrivingPrivilegeCodeClaim xmlDrivingPrivilegeCodeClaim = getXmlDrivingPrivilegeCodeClaim((VerifiedClaimDrivingPrivilegeCode) claimDrivingPrivilegeCode);
                    if (xmlDrivingPrivilegeCodeClaim != null) {
                        xmlDrivingPrivilegeCodesClaim.getCode().add(xmlDrivingPrivilegeCodeClaim);
                    }
                } else {
                    xmlDrivingPrivilegeCodesClaim.getItem().add(getXmlClaim(claimDrivingPrivilegeCode, supportedClaims));
                }
            }
        }
        return xmlDrivingPrivilegeCodesClaim;
    }

    private XmlDrivingPrivilegeCodeClaim getXmlDrivingPrivilegeCodeClaim(VerifiedClaimDrivingPrivilegeCode claimDrivingPrivilegeCode) {
        if (claimDrivingPrivilegeCode == null) {
            return null;
        }
        XmlDrivingPrivilegeCodeClaim xmlDrivingPrivilegeCodeClaim = new XmlDrivingPrivilegeCodeClaim();
        appendGenericInfo(xmlDrivingPrivilegeCodeClaim, claimDrivingPrivilegeCode);

        List<XmlClaim> claimSupportedClaims = new ArrayList<>();
        if (claimDrivingPrivilegeCode.getCode() != null) {
            xmlDrivingPrivilegeCodeClaim.setCode(getXmlClaim(claimDrivingPrivilegeCode.getCode(), claimSupportedClaims));
        }
        if (claimDrivingPrivilegeCode.getSign() != null) {
            xmlDrivingPrivilegeCodeClaim.setSign(getXmlClaim(claimDrivingPrivilegeCode.getSign(), claimSupportedClaims));
        }
        if (claimDrivingPrivilegeCode.getValue() != null) {
            xmlDrivingPrivilegeCodeClaim.setValue(getXmlClaim(claimDrivingPrivilegeCode.getValue(), claimSupportedClaims));
        }
        xmlDrivingPrivilegeCodeClaim.getEntry().addAll(getOtherClaims(claimDrivingPrivilegeCode, claimSupportedClaims));
        return xmlDrivingPrivilegeCodeClaim;
    }

    private XmlAgeEqualOrOverClaim getXmlAgeEqualOrOverClaim(VerifiedClaimAgeEqualOrOver claimAgeEqualOrOver, List<XmlClaim> supportedClaims) {
        if (claimAgeEqualOrOver == null) {
            return null;
        }
        XmlAgeEqualOrOverClaim xmlAgeEqualOrOverClaim = new XmlAgeEqualOrOverClaim();
        appendGenericInfo(xmlAgeEqualOrOverClaim, claimAgeEqualOrOver, supportedClaims);

        List<XmlClaim> claimSupportedClaims = new ArrayList<>();
        xmlAgeEqualOrOverClaim.getAgeOverNNClaim().addAll(getXmlAgeOverNNClaims(claimAgeEqualOrOver.getAgeOverNNClaims(), claimSupportedClaims));
        xmlAgeEqualOrOverClaim.getEntry().addAll(getOtherClaims(claimAgeEqualOrOver, claimSupportedClaims));

        return xmlAgeEqualOrOverClaim;
    }

    private List<XmlAgeOverNNClaim> getXmlAgeOverNNClaims(List<VerifiedClaimAgeOverNN> claimsAgeOverNN, List<XmlClaim> supportedClaims) {
        if (Utils.isCollectionEmpty(claimsAgeOverNN)) {
            return Collections.emptyList();
        }
        final List<XmlAgeOverNNClaim> result = new ArrayList<>();
        for (VerifiedClaimAgeOverNN claimAgeOverNN : claimsAgeOverNN) {
            XmlAgeOverNNClaim xmlAgeOverNNClaim = getXmlAgeOverNNClaim(claimAgeOverNN, supportedClaims);
            if (xmlAgeOverNNClaim != null) {
                result.add(xmlAgeOverNNClaim);
            }
        }
        return result;
    }

    private XmlAgeOverNNClaim getXmlAgeOverNNClaim(VerifiedClaimAgeOverNN claimAgeOverNN, List<XmlClaim> supportedClaims) {
        if (claimAgeOverNN == null) {
            return null;
        }
        XmlAgeOverNNClaim xmlAgeOverNNClaim = getXmlClaim(claimAgeOverNN, new XmlAgeOverNNClaim(), supportedClaims);
        if (claimAgeOverNN.getAge() != null) {
            xmlAgeOverNNClaim.setAge(claimAgeOverNN.getAge());
        }
        return xmlAgeOverNNClaim;
    }

    private List<XmlBiometricTemplateXXClaim> getXmlBiometricTemplateXXClaim(List<VerifiedClaimBiometricTemplateXX> claimsBiometricTemplateXX, List<XmlClaim> supportedClaims) {
        if (Utils.isCollectionEmpty(claimsBiometricTemplateXX)) {
            return Collections.emptyList();
        }
        final List<XmlBiometricTemplateXXClaim> result = new ArrayList<>();
        for (VerifiedClaimBiometricTemplateXX claimBiometricTemplateXX : claimsBiometricTemplateXX) {
            XmlBiometricTemplateXXClaim xmlBiometricTemplateXXClaim = getXmlBiometricTemplateXXClaim(claimBiometricTemplateXX, supportedClaims);
            if (xmlBiometricTemplateXXClaim != null) {
                result.add(xmlBiometricTemplateXXClaim);
            }
        }
        return result;
    }

    private XmlBiometricTemplateXXClaim getXmlBiometricTemplateXXClaim(VerifiedClaimBiometricTemplateXX claimBiometricTemplateXX, List<XmlClaim> supportedClaims) {
        if (claimBiometricTemplateXX == null) {
            return null;
        }
        XmlBiometricTemplateXXClaim xmlBiometricTemplateXXClaim = getXmlClaim(claimBiometricTemplateXX, new XmlBiometricTemplateXXClaim(), supportedClaims);
        if (claimBiometricTemplateXX.getType() != null) {
            xmlBiometricTemplateXXClaim.setType(claimBiometricTemplateXX.getType());
        }
        return xmlBiometricTemplateXXClaim;
    }

    private XmlAttestedAttributesSubjectClaim getXmlAttestedAttributesSubjectClaim(VerifiedClaimAttestedAttributesSubject attestedAttributesSubject, List<XmlClaim> supportedClaims) {
        if (attestedAttributesSubject == null) {
            return null;
        }

        XmlAttestedAttributesSubjectClaim xmlAttestedAttributesSubject = new XmlAttestedAttributesSubjectClaim();
        appendGenericInfo(xmlAttestedAttributesSubject, attestedAttributesSubject, supportedClaims);

        List<XmlClaim> claimSupportedClaims = new ArrayList<>();
        if (attestedAttributesSubject.getSubjectId() != null) {
            xmlAttestedAttributesSubject.setSubjectId(getXmlAttestedAttributesSubjectIdClaim(attestedAttributesSubject.getSubjectId(), claimSupportedClaims));
        }
        if (attestedAttributesSubject.getPseudonym() != null) {
            xmlAttestedAttributesSubject.setSubjectPseudonym(getXmlClaim(attestedAttributesSubject.getPseudonym(), claimSupportedClaims));
        }
        if (attestedAttributesSubject.getAttributes() != null) {
            xmlAttestedAttributesSubject.setAttributes(getXmlClaim(attestedAttributesSubject.getAttributes(), claimSupportedClaims));
        }
        xmlAttestedAttributesSubject.getEntry().addAll(getOtherClaims(attestedAttributesSubject, claimSupportedClaims));
        return xmlAttestedAttributesSubject;
    }

    private XmlAttestedAttributesSubjectIdClaim getXmlAttestedAttributesSubjectIdClaim(VerifiedClaim claim, List<XmlClaim> supportedClaims) {
        if (claim == null) {
            return null;
        }

        if (claim instanceof VerifiedClaimAttestedAttributesSubjectId) {
            XmlAttestedAttributesSubjectIdClaim xmlAttestedAttributesSubjectIdClaim = new XmlAttestedAttributesSubjectIdClaim();
            appendGenericInfo(xmlAttestedAttributesSubjectIdClaim, claim, supportedClaims);

            List<XmlClaim> claimSupportedClaims = new ArrayList<>();

            VerifiedClaimAttestedAttributesSubjectId attestedAttributesSubjectId = (VerifiedClaimAttestedAttributesSubjectId) claim;
            if (attestedAttributesSubjectId.getFamilyName() != null) {
                xmlAttestedAttributesSubjectIdClaim.setFamilyName(getXmlClaim(attestedAttributesSubjectId.getFamilyName(), claimSupportedClaims));
            }
            if (attestedAttributesSubjectId.getGivenName() != null) {
                xmlAttestedAttributesSubjectIdClaim.setGivenName(getXmlClaim(attestedAttributesSubjectId.getGivenName(), claimSupportedClaims));
            }
            if (attestedAttributesSubjectId.getDocumentNumber() != null) {
                xmlAttestedAttributesSubjectIdClaim.setDocumentNumber(getXmlClaim(attestedAttributesSubjectId.getDocumentNumber(), claimSupportedClaims));
            }
            xmlAttestedAttributesSubjectIdClaim.getEntry().addAll(getOtherClaims(claim, claimSupportedClaims));
            return xmlAttestedAttributesSubjectIdClaim;
        }
        return getXmlClaim(claim, new XmlAttestedAttributesSubjectIdClaim(), supportedClaims);
    }

    private List<XmlClaim> getOtherClaims(VerifiedClaim claim, List<XmlClaim> supportedClaims) {
        if (claim.isMapValueType() && !claim.isNullOrEmpty()) {
            final List<XmlClaim> otherClaims = new ArrayList<>();
            Collection<String> processedHeaderNames = getHeaderNames(supportedClaims);
            Map<String, VerifiedClaim> mapValue = claim.getMapValue();
            for (String headerName : mapValue.keySet()) {
                if (!processedHeaderNames.contains(headerName)) {
                    VerifiedClaim claimValue = mapValue.get(headerName);
                    if (claimValue != null) {
                        XmlClaim otherClaim = getXmlClaim(claimValue);
                        otherClaims.add(otherClaim);
                    }
                }
            }
            return otherClaims;
        }

        return Collections.emptyList();
    }

    private Collection<String> getHeaderNames(List<XmlClaim> claimsList) {
        Set<String> result = new HashSet<>();
        for (XmlClaim xmlClaim : claimsList) {
            addHeaderNameSecurely(xmlClaim, result);
        }
        return result;
    }

    private void addHeaderNameSecurely(XmlClaim xmlClaim, Set<String> result) {
        if (xmlClaim != null && xmlClaim.getName() != null) {
            result.add(xmlClaim.getName());
        }
    }

    private void appendGenericInfo(XmlClaim xmlClaim, VerifiedClaim claim) {
        appendGenericInfo(xmlClaim, claim, null);
    }

    private void appendGenericInfo(XmlClaim xmlClaim, VerifiedClaim claim, List<XmlClaim> supportedClaims) {
        if (claim != null) {
            if (claim.getName() != null) {
                xmlClaim.setName(claim.getName());
            }
            if (claim.getNamespace() != null) {
                xmlClaim.setNamespace(claim.getNamespace());
            }
            if (claim.isSelectivelyDisclosable()) {
                xmlClaim.setDisclosure(claim.isSelectivelyDisclosable());
            }
            if (supportedClaims != null) {
                supportedClaims.add(xmlClaim);
            }
        }
    }

    @Override
    public XmlSignature buildDetachedXmlSignature(AdvancedSignature signature) {
        return signatureDiagnosticDataBuilder.buildDetachedXmlSignature(signature);
    }

    private List<XmlAttestationRevocationToken> buildXmlAttestationRevocationTokens(Collection<AttestationRevocationToken> statusTokens) {
        List<XmlAttestationRevocationToken> xmlAttestationRevocationTokens = new ArrayList<>();
        if (Utils.isCollectionNotEmpty(statusTokens)) {
            List<AttestationRevocationToken> tokens = new ArrayList<>(statusTokens);
            tokens.sort(new TokenComparator());
            List<String> uniqueIds = new ArrayList<>(); // possible that attestations share one attestation Status List
            for (AttestationRevocationToken attestationRevocationToken : tokens) {
                String id = attestationRevocationToken.getDSSIdAsString();
                if (uniqueIds.contains(id)) {
                    continue;
                }
                XmlAttestationRevocationToken xmlAttestationRevocationToken = xmlAttestationRevocationTokenMap.get(id);
                if (xmlAttestationRevocationToken == null) {
                    xmlAttestationRevocationToken = buildDetachedXmlAttestationRevocationToken(attestationRevocationToken);
                    xmlAttestationRevocationTokenMap.put(id, xmlAttestationRevocationToken);
                    xmlAttestationRevocationTokens.add(xmlAttestationRevocationToken);
                }
                uniqueIds.add(id);
            }
        }
        return xmlAttestationRevocationTokens;

    }

    /**
     * Builds a new {@code XmlAttestationRevocationToken}
     *
     * @param attestationRevocationToken {@link AttestationRevocationToken}
     * @return {@link XmlAttestationRevocationToken}
     */
    protected XmlAttestationRevocationToken buildDetachedXmlAttestationRevocationToken(AttestationRevocationToken attestationRevocationToken) {
        final XmlAttestationRevocationToken xmlAttestationRevocationToken = new XmlAttestationRevocationToken();
        xmlAttestationRevocationToken.setId(identifierProvider.getIdAsString(attestationRevocationToken));
        xmlAttestationRevocationToken.setOrigin(attestationRevocationToken.getOrigin());
        xmlAttestationRevocationToken.setType(attestationRevocationToken.getType());
        xmlAttestationRevocationToken.setSourceAddress(attestationRevocationToken.getSourceURL());
        xmlAttestationRevocationToken.setSubject(getXmlAttestationSubject(attestationRevocationToken));
        xmlAttestationRevocationToken.setIssuedAt(attestationRevocationToken.getCreationDate());
        xmlAttestationRevocationToken.setExpirationTime(attestationRevocationToken.getExpirationDate());
        if (attestationRevocationToken.getTimeToLive() != null) {
            xmlAttestationRevocationToken.setTimeToLive(BigInteger.valueOf(attestationRevocationToken.getTimeToLive().longValue()));
        }

        setSignatureInfo(xmlAttestationRevocationToken, attestationRevocationToken);
        xmlAttestationRevocationToken.setFoundCertificates(getXmlFoundCertificates(attestationRevocationToken));

        if (tokenExtractionStrategy.isRevocationData()) {
            xmlAttestationRevocationToken.setBase64Encoded(attestationRevocationToken.getEncoded());
        } else {
            byte[] revocationDigest = attestationRevocationToken.getDigest(defaultDigestAlgorithm);
            xmlAttestationRevocationToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, revocationDigest));
        }

        return xmlAttestationRevocationToken;
    }

    private XmlAttestationSubject getXmlAttestationSubject(AttestationRevocationToken attestationRevocationToken) {
        if (attestationRevocationToken.getSubject() == null) {
            return null;
        }
        XmlAttestationSubject xmlAttestationSubject = new XmlAttestationSubject();
        xmlAttestationSubject.setValue(attestationRevocationToken.getSubject());
        if (attestationRevocationToken.getSubjectMatch() != null) {
            xmlAttestationSubject.setMatch(attestationRevocationToken.getSubjectMatch());
        }
        return xmlAttestationSubject;
    }

    private void setSignatureInfo(XmlAttestationRevocationToken xmlAttestationRevocationToken, AttestationRevocationToken attestationRevocationToken) {
        AdvancedSignature signature = attestationRevocationToken.getSignature();
        if (signature != null) {
            final CandidatesForSigningCertificate candidatesForSigningCertificate = signature.getCandidatesForSigningCertificate();
            final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
            PublicKey signingCertificatePublicKey = null;
            if (theCertificateValidity != null) {
                xmlAttestationRevocationToken.setSigningCertificate(getXmlSigningCertificate(attestationRevocationToken.getDSSId(), theCertificateValidity));
                xmlAttestationRevocationToken.setCertificateChain(getXmlForCertificateChain(theCertificateValidity, signature.getCertificateSource()));
                signingCertificatePublicKey = theCertificateValidity.getPublicKey();
            }

            xmlAttestationRevocationToken.setBasicSignature(getXmlBasicSignature(signature, signingCertificatePublicKey));
        }
    }

    private XmlFoundCertificates getXmlFoundCertificates(AttestationRevocationToken attestationRevocationToken) {
        final XmlFoundCertificates xmlFoundCertificates = new XmlFoundCertificates();
        if (attestationRevocationToken.getSignature() != null) {
            XmlFoundCertificates signatureFoundCertificates = getXmlFoundCertificates(
                    attestationRevocationToken.getSignature().getDSSId(), attestationRevocationToken.getSignature().getCertificateSource());
            populate(xmlFoundCertificates, signatureFoundCertificates);
        }
        if (attestationRevocationToken.getCertificateSource() != null) {
            XmlFoundCertificates statusListFoundCertificates = getXmlFoundCertificates(attestationRevocationToken.getDSSId(), attestationRevocationToken.getCertificateSource());
            populate(xmlFoundCertificates, statusListFoundCertificates);
        }
        return xmlFoundCertificates;
    }

    private void populate(XmlFoundCertificates result, XmlFoundCertificates foundCertificates) {
        if (Utils.isCollectionNotEmpty(foundCertificates.getRelatedCertificates())) {
            for (XmlRelatedCertificate xmlRelatedCertificate : foundCertificates.getRelatedCertificates()) {
                List<XmlRelatedCertificate> matchingCertificates = result.getRelatedCertificates().stream()
                        .filter(c -> xmlRelatedCertificate.getCertificate().getId().equals(c.getCertificate().getId()))
                        .collect(Collectors.toList());
                if (Utils.isCollectionNotEmpty(matchingCertificates)) {
                    XmlRelatedCertificate resultRelatedCertificate = matchingCertificates.get(0); // only one is expected
                    for (CertificateOrigin certificateOrigin : xmlRelatedCertificate.getOrigins()) {
                        if (!resultRelatedCertificate.getOrigins().contains(certificateOrigin)) {
                            resultRelatedCertificate.getOrigins().add(certificateOrigin);
                        }
                    }
                    resultRelatedCertificate.getCertificateRefs().addAll(xmlRelatedCertificate.getCertificateRefs());

                } else {
                    result.getRelatedCertificates().add(xmlRelatedCertificate);
                }
            }
        }
        if (Utils.isCollectionNotEmpty(foundCertificates.getOrphanCertificates())) {
            for (XmlOrphanCertificate xmlOrphanCertificate : foundCertificates.getOrphanCertificates()) {
                List<XmlOrphanCertificate> matchingCertificates = result.getOrphanCertificates().stream()
                        .filter(c -> xmlOrphanCertificate.getToken().getId().equals(c.getToken().getId()))
                        .collect(Collectors.toList());
                if (Utils.isCollectionNotEmpty(matchingCertificates)) {
                    XmlOrphanCertificate resultOrphanCertificate = matchingCertificates.get(0); // only one is expected
                    for (CertificateOrigin certificateOrigin : xmlOrphanCertificate.getOrigins()) {
                        if (!resultOrphanCertificate.getOrigins().contains(certificateOrigin)) {
                            resultOrphanCertificate.getOrigins().add(certificateOrigin);
                        }
                    }
                    resultOrphanCertificate.getCertificateRefs().addAll(xmlOrphanCertificate.getCertificateRefs());

                } else {
                    result.getOrphanCertificates().add(xmlOrphanCertificate);
                }
            }
        }
    }

    private void linkAttestationAndRevocations(Collection<Attestation> attestations) {
        if (Utils.isCollectionNotEmpty(attestations)) {
            for (Attestation attestation : attestations) {
                XmlAttestation xmlAttestation = xmlAttestationMap.get(attestation.getId());
                Set<AttestationRevocationToken> revocationTokens = getRevocationTokensForAttestation(attestation);
                for (AttestationRevocationToken revocationToken : revocationTokens) {
                    XmlAttestationRevocationToken xmlAttestationRevocationToken = xmlAttestationRevocationTokenMap.get(revocationToken.getDSSIdAsString());
                    XmlAttestationRevocationStatus xmlAttestationRevocationStatus = new XmlAttestationRevocationStatus();
                    xmlAttestationRevocationStatus.setAttestationRevocationToken(xmlAttestationRevocationToken);
                    xmlAttestationRevocationStatus.setStatus(revocationToken.getStatus());
                    xmlAttestation.getAttestationRevocations().add(xmlAttestationRevocationStatus);
                }
            }
        }
    }

    private Set<AttestationRevocationToken> getRevocationTokensForAttestation(Attestation attestation) {
        Set<AttestationRevocationToken> statuses = new HashSet<>();
        if (Utils.isCollectionNotEmpty(attestationRevocationTokens)) {
            for (AttestationRevocationToken attestationRevocationToken : attestationRevocationTokens) {
                if (Utils.areStringsEqual(attestation.getId(), attestationRevocationToken.getRelatedAttestationId())) {
                    statuses.add(attestationRevocationToken);
                }
            }
        }
        return statuses;
    }

}
