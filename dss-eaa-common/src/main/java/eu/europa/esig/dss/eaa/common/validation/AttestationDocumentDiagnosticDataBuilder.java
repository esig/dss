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
package eu.europa.esig.dss.eaa.common.validation;

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
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAA;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAADocument;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAAPayload;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAAPresentationInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAASignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAARevocationStatus;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAARevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAASubject;
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
import eu.europa.esig.dss.model.eaa.DisclosureValidation;
import eu.europa.esig.dss.model.eaa.claim.Claim;
import eu.europa.esig.dss.model.eaa.claim.ClaimAddress;
import eu.europa.esig.dss.model.eaa.claim.ClaimAgeEqualOrOver;
import eu.europa.esig.dss.model.eaa.claim.ClaimAgeOverNN;
import eu.europa.esig.dss.model.eaa.claim.ClaimAttestedAttributesSubject;
import eu.europa.esig.dss.model.eaa.claim.ClaimAttestedAttributesSubjectId;
import eu.europa.esig.dss.model.eaa.claim.ClaimBiometricTemplateXX;
import eu.europa.esig.dss.model.eaa.claim.ClaimBirthDate;
import eu.europa.esig.dss.model.eaa.claim.ClaimCredentialSubject;
import eu.europa.esig.dss.model.eaa.claim.ClaimDeviceKey;
import eu.europa.esig.dss.model.eaa.claim.ClaimDrivingPrivilege;
import eu.europa.esig.dss.model.eaa.claim.ClaimDrivingPrivilegeCode;
import eu.europa.esig.dss.model.eaa.claim.ClaimDrivingPrivilegeCodes;
import eu.europa.esig.dss.model.eaa.claim.ClaimDrivingPrivileges;
import eu.europa.esig.dss.model.eaa.claim.ClaimIdentifierList;
import eu.europa.esig.dss.model.eaa.claim.ClaimIntegrity;
import eu.europa.esig.dss.model.eaa.claim.ClaimPlaceOfBirth;
import eu.europa.esig.dss.model.eaa.claim.ClaimStatus;
import eu.europa.esig.dss.model.eaa.claim.ClaimStatusList;
import eu.europa.esig.dss.model.eaa.claim.ClaimString;
import eu.europa.esig.dss.model.eaa.claim.ClaimValidityInfo;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.TokenComparator;
import eu.europa.esig.dss.spi.eaa.Attestation;
import eu.europa.esig.dss.spi.eaa.AttestationPresentation;
import eu.europa.esig.dss.spi.eaa.AttestationRevocationToken;
import eu.europa.esig.dss.spi.eaa.KeyBindingSignaturePayload;
import eu.europa.esig.dss.spi.eaa.AttestationPayload;
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
 * Builds DiagnosticData for a presentation of Electronic Attestation of Attributes validation
 *
 */
public class AttestationDocumentDiagnosticDataBuilder extends SignedDocumentDiagnosticDataBuilder {

    /** The EAA presentation */
    protected AttestationPresentation attestationPresentation;

    /** Collection of EAA revocation tokens acquired during the validation */
    protected Collection<AttestationRevocationToken> attestationRevocationTokens;

    /** Builder used to build a signature object */
    private SignedDocumentDiagnosticDataBuilder signatureDiagnosticDataBuilder;

    /** The cached map of EAAs */
    protected Map<String, XmlEAA> xmlEAAMap = new HashMap<>();

    /** The cached map of EAA revocation tokens */
    protected Map<String, XmlEAARevocationToken> xmlEAARevocationTokenMap = new HashMap<>();

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
            xmlDiagnosticData.setEAAPresentationInfo(buildXmlEAAPresentationInfo(attestationPresentation));
            List<Attestation> attestations = attestationPresentation.getElectronicAttestationsOfAttributes();
            Collection<XmlEAA> xmlEAAs = buildXmlEAA(attestations);
            xmlDiagnosticData.getEAAs().addAll(xmlEAAs);

            if (Utils.isCollectionNotEmpty(attestationRevocationTokens)) {
                xmlDiagnosticData.getUsedEAARevocationTokens().addAll(buildXmlEAARevocationTokens(attestationRevocationTokens));
                linkEAAAndStatuses(attestationPresentation.getElectronicAttestationsOfAttributes());
            }
        }
        xmlDiagnosticData.setOrphanTokens(buildXmlOrphanTokens());
        return xmlDiagnosticData;
    }

    /**
     * Builds {@code XmlEAAPresentationInfo} based on the {@code EAAPresentation}
     *
     * @param attestationPresentation {@link AttestationPresentation}
     * @return {@link XmlEAAPresentationInfo}
     */
    protected XmlEAAPresentationInfo buildXmlEAAPresentationInfo(AttestationPresentation attestationPresentation) {
        final XmlEAAPresentationInfo xmlEAAPresentationInfo = new XmlEAAPresentationInfo();
        xmlEAAPresentationInfo.setEAAPresentationType(attestationPresentation.getEAAPresentationType());
        if (Utils.isCollectionNotEmpty(attestationPresentation.getElectronicAttestationsOfAttributes())) {
            for (Attestation attestation : attestationPresentation.getElectronicAttestationsOfAttributes()) {
                xmlEAAPresentationInfo.getDocuments().add(buildXmlEAADocument(attestation));
            }
        }
        return xmlEAAPresentationInfo;
    }

    /**
     * Builds an instance of {@code XmlEAADocument} for a {@code EAA}
     *
     * @param attestation {@link Attestation}
     * @return {@link XmlEAADocument}
     */
    protected XmlEAADocument buildXmlEAADocument(Attestation attestation) {
        final XmlEAADocument xmlEAADocument = new XmlEAADocument();
        xmlEAADocument.setEAA(getXmlEAA(attestation));
        return xmlEAADocument;
    }

    private Collection<XmlEAA> buildXmlEAA(Collection<Attestation> attestations) {
        List<XmlEAA> builtEAAPresentations = new ArrayList<>();
        for (Attestation attestation : attestations) {
            XmlEAA xmlEAAPresentation = getXmlEAA(attestation);
            builtEAAPresentations.add(xmlEAAPresentation);
        }
        return builtEAAPresentations;
    }

    private XmlEAA getXmlEAA(Attestation attestation) {
        return xmlEAAMap.computeIfAbsent(attestation.getId(), k -> buildDetachedXmlEAA(attestation));
    }

    /**
     * Builds an {@code XmlEAA} instance
     *
     * @param attestation {@link Attestation}
     * @return {@link XmlEAA}
     */
    protected XmlEAA buildDetachedXmlEAA(Attestation attestation) {
        final XmlEAA xmlEAAPresentation = new XmlEAA();
        xmlEAAPresentation.setId(identifierProvider.getIdAsString(attestation));
        xmlEAAPresentation.setDocumentName(attestation.getFilename());
        xmlEAAPresentation.setEAAType(attestation.getEAAType());
        for (AdvancedSignature signature : attestation.getSignatures()) {
            xmlEAAPresentation.getEAASignature().add(getXmlEAASignature(signature));
        }
        xmlEAAPresentation.setDigestMethod(attestation.getSelectiveDisclosuresDigestAlgorithm());
        xmlEAAPresentation.setDigestMatchers(buildXmlDigestMatchers(attestation.getDisclosureValidations()));
        if (attestation.getKeyBindingSignature() != null) {
            xmlEAAPresentation.setKeyBindingSignature(getXmlKeyBindingSignature(attestation.getKeyBindingSignature()));
        }
        xmlEAAPresentation.setEAAPayload(getXmlEAAPayload(attestation.getPayload()));
        xmlEAAPresentation.setKeyBindingPayload(getXmlKeyBindingPayload(attestation.getKeyBindingSignaturePayload()));
        return xmlEAAPresentation;
    }

    private XmlEAASignature getXmlEAASignature(AdvancedSignature signature) {
        XmlEAASignature xmlEAAPresentationSignature = new XmlEAASignature();
        XmlSignature xmlSignature = xmlSignaturesMap.get(signature.getId());
        if (xmlSignature == null) {
            throw new IllegalStateException(String.format(
                    "XmlSignature shall be built at this moment! Not found signature with id '%s'.", signature.getId()));
        }
        xmlEAAPresentationSignature.setSignature(xmlSignature);
        return xmlEAAPresentationSignature;
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

    private XmlEAAPayload getXmlEAAPayload(AttestationPayload attestationPayload) {
        final List<XmlClaim> supportedClaims = new ArrayList<>();
        final XmlEAAPayload xmlEAAPayload = new XmlEAAPayload();

        xmlEAAPayload.setIdentifier(getXmlClaim(attestationPayload.getIdentifier(), supportedClaims));
        xmlEAAPayload.setIssuer(getXmlClaim(attestationPayload.getIssuer(), supportedClaims));
        xmlEAAPayload.setSubject(getXmlClaim(attestationPayload.getSubject(), supportedClaims));
        xmlEAAPayload.setAudience(getXmlClaim(attestationPayload.getAudience(), supportedClaims));
        xmlEAAPayload.setExpiration(getXmlClaim(attestationPayload.getExpirationTime(), supportedClaims));
        xmlEAAPayload.setNotBefore(getXmlClaim(attestationPayload.getNotBeforeTime(), supportedClaims));
        xmlEAAPayload.setIssuedAt(getXmlClaim(attestationPayload.getIssuedAtTime(), supportedClaims));
        xmlEAAPayload.setUpdatedAt(getXmlClaim(attestationPayload.getUpdatedAtTime(), supportedClaims));
        xmlEAAPayload.setCategory(getXmlClaim(attestationPayload.getCategory(), supportedClaims));
        xmlEAAPayload.setVerifiableCredentialsType(getXmlVerifiableCredentialsType(attestationPayload, supportedClaims));
        xmlEAAPayload.setStatus(getXmlStatus(attestationPayload.getStatus(), supportedClaims));
        xmlEAAPayload.setNonce(getXmlClaim(attestationPayload.getNonce(), supportedClaims));
        xmlEAAPayload.setDeviceKey(getXmlDeviceKeyClaim(attestationPayload.getDeviceKey(), supportedClaims));

        xmlEAAPayload.setVersion(getXmlClaim(attestationPayload.getVersion(), supportedClaims));
        xmlEAAPayload.setDocType(getXmlClaim(attestationPayload.getDocType(), supportedClaims));
        xmlEAAPayload.setValidityInfo(getXmlValidityInfoClaim(attestationPayload.getValidityInfo(), supportedClaims));

        xmlEAAPayload.setAdministrativeIssuanceDate(getXmlClaim(attestationPayload.getAdministrativeIssuanceDate(), supportedClaims));
        xmlEAAPayload.setAdministrativeExpirationDate(getXmlClaim(attestationPayload.getAdministrativeExpirationDate(), supportedClaims));
        xmlEAAPayload.setOneTimeUse(getXmlClaim(attestationPayload.getOneTimeUse(), supportedClaims));
        xmlEAAPayload.setShortLived(getXmlClaim(attestationPayload.getShortLived(), supportedClaims));
        xmlEAAPayload.setEvidence(getXmlClaim(attestationPayload.getEvidence(), supportedClaims));
        xmlEAAPayload.setAttestedAttributesSubject(getXmlAttestedAttributesSubjectClaim(attestationPayload.getAttestedAttributesSubject(), supportedClaims)); // TODO : enhance with AttestedAttributesSubjectWrapper

        xmlEAAPayload.setFullName(getXmlClaim(attestationPayload.getFullName(), supportedClaims));
        xmlEAAPayload.setGivenName(getXmlClaim(attestationPayload.getGivenName(), supportedClaims));
        xmlEAAPayload.setFamilyName(getXmlClaim(attestationPayload.getFamilyName(), supportedClaims));
        xmlEAAPayload.setMiddleName(getXmlClaim(attestationPayload.getMiddleName(), supportedClaims));
        xmlEAAPayload.setNickname(getXmlClaim(attestationPayload.getNickname(), supportedClaims));
        xmlEAAPayload.setShortName(getXmlClaim(attestationPayload.getShortName(), supportedClaims));
        xmlEAAPayload.setProfileUrl(getXmlClaim(attestationPayload.getProfileUrl(), supportedClaims));
        xmlEAAPayload.setPictureUrl(getXmlClaim(attestationPayload.getPictureUrl(), supportedClaims));
        xmlEAAPayload.setWebsiteUrl(getXmlClaim(attestationPayload.getWebsiteUrl(), supportedClaims));
        xmlEAAPayload.setEmail(getXmlClaim(attestationPayload.getEmail(), supportedClaims));
        xmlEAAPayload.setEmailVerified(getXmlClaim(attestationPayload.getEmailVerified(), supportedClaims));
        xmlEAAPayload.setGender(getXmlClaim(attestationPayload.getGender(), supportedClaims));
        xmlEAAPayload.setBirthdate(getXmlBirthdateClaim(attestationPayload.getBirthdate(), supportedClaims));
        xmlEAAPayload.setTimezone(getXmlClaim(attestationPayload.getTimezone(), supportedClaims));
        xmlEAAPayload.setLocale(getXmlClaim(attestationPayload.getLocale(), supportedClaims));
        xmlEAAPayload.setAddress(getXmlAddressClaim(attestationPayload.getAddress(), supportedClaims));
        xmlEAAPayload.setPhoneNumber(getXmlClaim(attestationPayload.getPhoneNumber(), supportedClaims));
        xmlEAAPayload.setPhoneNumberVerified(getXmlClaim(attestationPayload.getPhoneNumberVerified(), supportedClaims));
        xmlEAAPayload.setPlaceOfBirth(getXmlPlaceOfBirthClaim(attestationPayload.getPlaceOfBirth(), supportedClaims));
        xmlEAAPayload.setNationalities(getXmlClaim(attestationPayload.getNationalities(), supportedClaims));
        xmlEAAPayload.setBirthFamilyName(getXmlClaim(attestationPayload.getBirthFamilyName(), supportedClaims));
        xmlEAAPayload.setBirthGivenName(getXmlClaim(attestationPayload.getBirthGivenName(), supportedClaims));
        xmlEAAPayload.setBirthMiddleName(getXmlClaim(attestationPayload.getBirthMiddleName(), supportedClaims));
        xmlEAAPayload.setSalutation(getXmlClaim(attestationPayload.getSalutation(), supportedClaims));
        xmlEAAPayload.setTitle(getXmlClaim(attestationPayload.getTitle(), supportedClaims));
        xmlEAAPayload.setMobilePhoneNumber(getXmlClaim(attestationPayload.getMobilePhoneNumber(), supportedClaims));
        xmlEAAPayload.setPseudonym(getXmlClaim(attestationPayload.getPseudonym(), supportedClaims));
        xmlEAAPayload.getCredentialSubject().addAll(getXmlCredentialSubjectClaimList(attestationPayload.getCredentialSubjects(), supportedClaims));

        xmlEAAPayload.setIssuingCountry(getXmlClaim(attestationPayload.getIssuingCountry(), supportedClaims));
        xmlEAAPayload.setIssuingAuthority(getXmlClaim(attestationPayload.getIssuingAuthority(), supportedClaims));
        xmlEAAPayload.setDocumentNumber(getXmlClaim(attestationPayload.getDocumentNumber(), supportedClaims));
        xmlEAAPayload.setPortrait(getXmlClaim(attestationPayload.getPortrait(), supportedClaims));
        xmlEAAPayload.setDrivingPrivileges(getXmlDrivingPrivilegesClaim(attestationPayload.getDrivingPrivileges(), supportedClaims));
        xmlEAAPayload.setUNDistinguishingSign(getXmlClaim(attestationPayload.getUNDistinguishingSign(), supportedClaims));
        xmlEAAPayload.setPersonalAdministrativeNumber(getXmlClaim(attestationPayload.getPersonalAdministrativeNumber(), supportedClaims));
        xmlEAAPayload.setHeight(getXmlClaim(attestationPayload.getHeight(), supportedClaims));
        xmlEAAPayload.setWeight(getXmlClaim(attestationPayload.getWeight(), supportedClaims));
        xmlEAAPayload.setEyeColour(getXmlClaim(attestationPayload.getEyeColour(), supportedClaims));
        xmlEAAPayload.setHairColour(getXmlClaim(attestationPayload.getHairColour(), supportedClaims));
        xmlEAAPayload.setResidentPostalAddress(getXmlClaim(attestationPayload.getPostalAddress(), supportedClaims));
        xmlEAAPayload.setPortraitCaptureDate(getXmlClaim(attestationPayload.getPortraitCaptureDate(), supportedClaims));
        xmlEAAPayload.setAgeInYears(getXmlClaim(attestationPayload.getAgeInYears(), supportedClaims));
        xmlEAAPayload.setAgeBirthYear(getXmlClaim(attestationPayload.getAgeBirthYear(), supportedClaims));
        xmlEAAPayload.setAgeEqualOrOver(getXmlAgeEqualOrOverClaim(attestationPayload.getAgeEqualOrOver(), supportedClaims));
        xmlEAAPayload.getAgeOverNN().addAll(getXmlAgeOverNNClaims(attestationPayload.getAgeOverNN(), supportedClaims));
        xmlEAAPayload.setIssuingJurisdiction(getXmlClaim(attestationPayload.getIssuingJurisdiction(), supportedClaims));
        xmlEAAPayload.setResidentAddressCity(getXmlClaim(attestationPayload.getResidentAddressCity(), supportedClaims));
        xmlEAAPayload.setResidentAddressState(getXmlClaim(attestationPayload.getResidentAddressState(), supportedClaims));
        xmlEAAPayload.setResidentAddressPostalCode(getXmlClaim(attestationPayload.getResidentAddressPostalCode(), supportedClaims));
        xmlEAAPayload.setResidentAddressCountry(getXmlClaim(attestationPayload.getResidentAddressCountry(), supportedClaims));
        xmlEAAPayload.getBiometricTemplate().addAll(getXmlBiometricTemplateXXClaim(attestationPayload.getBiometricTemplate(), supportedClaims));
        xmlEAAPayload.setSignatureUsualMark(getXmlClaim(attestationPayload.getSignatureUsualMark(), supportedClaims));
        xmlEAAPayload.setFingerprint(getXmlClaim(attestationPayload.getFingerprint(), supportedClaims));
        xmlEAAPayload.setBusinessName(getXmlClaim(attestationPayload.getBusinessName(), supportedClaims));
        xmlEAAPayload.setOrganizationName(getXmlClaim(attestationPayload.getOrganizationName(), supportedClaims));
        xmlEAAPayload.setBirthFullName(getXmlClaim(attestationPayload.getBirthFullName(), supportedClaims));
        xmlEAAPayload.setProfession(getXmlClaim(attestationPayload.getProfession(), supportedClaims));
        xmlEAAPayload.setRelationshipFather(getXmlClaim(attestationPayload.getRelationshipFather(), supportedClaims));
        xmlEAAPayload.setRelationshipMother(getXmlClaim(attestationPayload.getRelationshipMother(), supportedClaims));
        xmlEAAPayload.setRelationshipParent(getXmlClaim(attestationPayload.getRelationshipParent(), supportedClaims));
        xmlEAAPayload.setRelationshipSon(getXmlClaim(attestationPayload.getRelationshipSon(), supportedClaims));
        xmlEAAPayload.setRelationshipDaughter(getXmlClaim(attestationPayload.getRelationshipDaughter(), supportedClaims));
        xmlEAAPayload.setRelationshipBrother(getXmlClaim(attestationPayload.getRelationshipBrother(), supportedClaims));
        xmlEAAPayload.setRelationshipSister(getXmlClaim(attestationPayload.getRelationshipSister(), supportedClaims));
        xmlEAAPayload.setRelationshipSibling(getXmlClaim(attestationPayload.getRelationshipSibling(), supportedClaims));
        xmlEAAPayload.setRelationshipSpouse(getXmlClaim(attestationPayload.getRelationshipSpouse(), supportedClaims));
        xmlEAAPayload.setRelationshipFatherInLaw(getXmlClaim(attestationPayload.getRelationshipFatherInLaw(), supportedClaims));
        xmlEAAPayload.setRelationshipMotherInLaw(getXmlClaim(attestationPayload.getRelationshipMotherInLaw(), supportedClaims));
        xmlEAAPayload.setRelationshipParentInLaw(getXmlClaim(attestationPayload.getRelationshipParentInLaw(), supportedClaims));
        xmlEAAPayload.setRelationshipSonInLaw(getXmlClaim(attestationPayload.getRelationshipSonInLaw(), supportedClaims));
        xmlEAAPayload.setRelationshipDaughterInLaw(getXmlClaim(attestationPayload.getRelationshipDaughterInLaw(), supportedClaims));
        xmlEAAPayload.setRelationshipChildInLaw(getXmlClaim(attestationPayload.getRelationshipChildInLaw(), supportedClaims));
        xmlEAAPayload.setRelationshipParentalAuthority(getXmlClaim(attestationPayload.getRelationshipParentalAuthority(), supportedClaims));
        xmlEAAPayload.setRelationshipLegalRepresentative(getXmlClaim(attestationPayload.getRelationshipLegalRepresentative(), supportedClaims));
        xmlEAAPayload.setRelationshipAgent(getXmlClaim(attestationPayload.getRelationshipAgent(), supportedClaims));
        xmlEAAPayload.setDocumentType(getXmlClaim(attestationPayload.getDocumentType(), supportedClaims));

        xmlEAAPayload.setIssuingAuthorityRegistrationIdentifier(getXmlClaim(attestationPayload.getIssuingAuthorityRegistrationIdentifier(), supportedClaims));
        xmlEAAPayload.setTrustAnchor(getXmlClaim(attestationPayload.getTrustAnchor(), supportedClaims));
        xmlEAAPayload.setResidentAddressStreet(getXmlClaim(attestationPayload.getResidentAddressStreet(), supportedClaims));
        xmlEAAPayload.setResidentAddressHouseNumber(getXmlClaim(attestationPayload.getResidentAddressHouseNumber(), supportedClaims));

        xmlEAAPayload.getOtherClaim().addAll(getOtherClaims(attestationPayload, supportedClaims));

        return xmlEAAPayload;
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

    private XmlClaim getXmlClaim(Claim claim) {
        return getXmlClaim(claim, (List<XmlClaim>) null);
    }

    private XmlClaim getXmlClaim(Claim claim, List<XmlClaim> supportedClaims) {
        return getXmlClaim(claim, new XmlClaim(), supportedClaims);
    }

    private <T extends XmlClaim> T getXmlClaim(Claim claim, T xmlClaim) {
        return getXmlClaim(claim, xmlClaim, null);
    }

    private <T extends XmlClaim> T getXmlClaim(Claim claim, T xmlClaim, List<XmlClaim> supportedClaims) {
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
                for (Claim claimItem : claim.getListValue()) {
                    xmlClaim.getItem().add(getXmlClaim(claimItem, new XmlClaim()));
                }
            } else if (claim.isMapValueType()) {
                for (Map.Entry<String, Claim> entry : claim.getMapValue().entrySet()) {
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
        ClaimString metadata = attestationPayload.getVerifiableCredentialsType();
        if (metadata != null) {
            XmlVerifiableCredentialsTypeClaim xmlVerifiableCredentialsType = getXmlClaim(metadata, new XmlVerifiableCredentialsTypeClaim(), supportedClaims);
            if (attestationPayload.getVerifiableCredentialsTypeIntegrity() != null) {
                xmlVerifiableCredentialsType.setIntegrity(getXmlIntegrityClaim(attestationPayload.getVerifiableCredentialsTypeIntegrity(), supportedClaims));
            }
            return xmlVerifiableCredentialsType;
        }
        return null;
    }

    private XmlStatusClaim getXmlStatus(ClaimStatus claimStatus, List<XmlClaim> supportedClaims) {
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

    private XmlStatusListClaim getXmlStatusList(ClaimStatusList claimStatusList, List<XmlClaim> supportedClaims) {
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

    private XmlIdentifierListClaim getXmlIdentifierList(ClaimIdentifierList claimStatusList, List<XmlClaim> supportedClaims) {
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

    private XmlDeviceKeyClaim getXmlDeviceKeyClaim(ClaimDeviceKey deviceKey, List<XmlClaim> supportedClaims) {
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

    private XmlValidityInfoClaim getXmlValidityInfoClaim(ClaimValidityInfo validityInfo, List<XmlClaim> supportedClaims) {
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

    private XmlAddressClaim getXmlAddressClaim(ClaimAddress claimAddress, List<XmlClaim> supportedClaims) {
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

    private XmlBirthdateClaim getXmlBirthdateClaim(Claim claim, List<XmlClaim> supportedClaims) {
        if (claim == null) {
            return null;
        }
        if (claim instanceof ClaimBirthDate) {
            ClaimBirthDate claimBirthDate = (ClaimBirthDate) claim;
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

    private XmlPlaceOfBirthClaim getXmlPlaceOfBirthClaim(Claim claim, List<XmlClaim> supportedClaims) {
        if (claim == null) {
            return null;
        }
        if (claim instanceof ClaimPlaceOfBirth) {
            ClaimPlaceOfBirth claimPlaceOfBirth = (ClaimPlaceOfBirth) claim;
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

    private XmlIntegrityClaim getXmlIntegrityClaim(ClaimIntegrity claimIntegrity, List<XmlClaim> supportedClaims) {
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

    private List<XmlCredentialSubjectClaim> getXmlCredentialSubjectClaimList(List<ClaimCredentialSubject> credentialSubjects, List<XmlClaim> supportedClaims) {
        if (Utils.isCollectionEmpty(credentialSubjects)) {
            return Collections.emptyList();
        }
        return credentialSubjects.stream().map(s -> getXmlCredentialSubjectClaim(s, supportedClaims)).collect(Collectors.toList());
    }

    private XmlCredentialSubjectClaim getXmlCredentialSubjectClaim(ClaimCredentialSubject credentialSubject, List<XmlClaim> supportedClaims) {
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

    private XmlDrivingPrivilegesClaim getXmlDrivingPrivilegesClaim(ClaimDrivingPrivileges claimDrivingPrivileges, List<XmlClaim> supportedClaims) {
        if (claimDrivingPrivileges == null) {
            return null;
        }
        XmlDrivingPrivilegesClaim xmlDrivingPrivilegesClaim = new XmlDrivingPrivilegesClaim();
        appendGenericInfo(xmlDrivingPrivilegesClaim, claimDrivingPrivileges, supportedClaims);
        if (Utils.isCollectionNotEmpty(claimDrivingPrivileges.getListValue())) {
            for (Claim claimDrivingPrivilege : claimDrivingPrivileges.getListValue()) {
                if (claimDrivingPrivilege instanceof ClaimDrivingPrivilege) {
                    XmlDrivingPrivilegeClaim xmlDrivingPrivilegeClaim = getXmlDrivingPrivilegeClaim((ClaimDrivingPrivilege) claimDrivingPrivilege);
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

    private XmlDrivingPrivilegeClaim getXmlDrivingPrivilegeClaim(ClaimDrivingPrivilege claimDrivingPrivilege) {
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

    private XmlDrivingPrivilegeCodesClaim getXmlDrivingPrivilegeCodesClaim(ClaimDrivingPrivilegeCodes claimDrivingPrivilegeCodes, List<XmlClaim> supportedClaims) {
        if (claimDrivingPrivilegeCodes == null) {
            return null;
        }
        XmlDrivingPrivilegeCodesClaim xmlDrivingPrivilegeCodesClaim = new XmlDrivingPrivilegeCodesClaim();
        appendGenericInfo(xmlDrivingPrivilegeCodesClaim, claimDrivingPrivilegeCodes, supportedClaims);
        if (Utils.isCollectionNotEmpty(claimDrivingPrivilegeCodes.getListValue())) {
            for (Claim claimDrivingPrivilegeCode : claimDrivingPrivilegeCodes.getListValue()) {
                if (claimDrivingPrivilegeCode instanceof ClaimDrivingPrivilegeCode) {
                    XmlDrivingPrivilegeCodeClaim xmlDrivingPrivilegeCodeClaim = getXmlDrivingPrivilegeCodeClaim((ClaimDrivingPrivilegeCode) claimDrivingPrivilegeCode);
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

    private XmlDrivingPrivilegeCodeClaim getXmlDrivingPrivilegeCodeClaim(ClaimDrivingPrivilegeCode claimDrivingPrivilegeCode) {
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

    private XmlAgeEqualOrOverClaim getXmlAgeEqualOrOverClaim(ClaimAgeEqualOrOver claimAgeEqualOrOver, List<XmlClaim> supportedClaims) {
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

    private List<XmlAgeOverNNClaim> getXmlAgeOverNNClaims(List<ClaimAgeOverNN> claimsAgeOverNN, List<XmlClaim> supportedClaims) {
        if (Utils.isCollectionEmpty(claimsAgeOverNN)) {
            return Collections.emptyList();
        }
        final List<XmlAgeOverNNClaim> result = new ArrayList<>();
        for (ClaimAgeOverNN claimAgeOverNN : claimsAgeOverNN) {
            XmlAgeOverNNClaim xmlAgeOverNNClaim = getXmlAgeOverNNClaim(claimAgeOverNN, supportedClaims);
            if (xmlAgeOverNNClaim != null) {
                result.add(xmlAgeOverNNClaim);
            }
        }
        return result;
    }

    private XmlAgeOverNNClaim getXmlAgeOverNNClaim(ClaimAgeOverNN claimAgeOverNN, List<XmlClaim> supportedClaims) {
        if (claimAgeOverNN == null) {
            return null;
        }
        XmlAgeOverNNClaim xmlAgeOverNNClaim = getXmlClaim(claimAgeOverNN, new XmlAgeOverNNClaim(), supportedClaims);
        if (claimAgeOverNN.getAge() != null) {
            xmlAgeOverNNClaim.setAge(claimAgeOverNN.getAge());
        }
        return xmlAgeOverNNClaim;
    }

    private List<XmlBiometricTemplateXXClaim> getXmlBiometricTemplateXXClaim(List<ClaimBiometricTemplateXX> claimsBiometricTemplateXX, List<XmlClaim> supportedClaims) {
        if (Utils.isCollectionEmpty(claimsBiometricTemplateXX)) {
            return Collections.emptyList();
        }
        final List<XmlBiometricTemplateXXClaim> result = new ArrayList<>();
        for (ClaimBiometricTemplateXX claimBiometricTemplateXX : claimsBiometricTemplateXX) {
            XmlBiometricTemplateXXClaim xmlBiometricTemplateXXClaim = getXmlBiometricTemplateXXClaim(claimBiometricTemplateXX, supportedClaims);
            if (xmlBiometricTemplateXXClaim != null) {
                result.add(xmlBiometricTemplateXXClaim);
            }
        }
        return result;
    }

    private XmlBiometricTemplateXXClaim getXmlBiometricTemplateXXClaim(ClaimBiometricTemplateXX claimBiometricTemplateXX, List<XmlClaim> supportedClaims) {
        if (claimBiometricTemplateXX == null) {
            return null;
        }
        XmlBiometricTemplateXXClaim xmlBiometricTemplateXXClaim = getXmlClaim(claimBiometricTemplateXX, new XmlBiometricTemplateXXClaim(), supportedClaims);
        if (claimBiometricTemplateXX.getType() != null) {
            xmlBiometricTemplateXXClaim.setType(claimBiometricTemplateXX.getType());
        }
        return xmlBiometricTemplateXXClaim;
    }

    private XmlAttestedAttributesSubjectClaim getXmlAttestedAttributesSubjectClaim(ClaimAttestedAttributesSubject attestedAttributesSubject, List<XmlClaim> supportedClaims) {
        if (attestedAttributesSubject == null) {
            return null;
        }

        XmlAttestedAttributesSubjectClaim xmlAttestedAttributesSubject = new XmlAttestedAttributesSubjectClaim();
        appendGenericInfo(xmlAttestedAttributesSubject, attestedAttributesSubject, supportedClaims);

        List<XmlClaim> claimSupportedClaims = new ArrayList<>();
        if (attestedAttributesSubject.getSubjectId() != null) {
            xmlAttestedAttributesSubject.setSubjectId(getXmlAttestedAttributesSubjectIdClaim(attestedAttributesSubject.getSubjectId(), claimSupportedClaims));
        }
        if (attestedAttributesSubject.getSubjectPseudonym() != null) {
            xmlAttestedAttributesSubject.setSubjectPseudonym(getXmlClaim(attestedAttributesSubject.getSubjectPseudonym(), claimSupportedClaims));
        }
        if (attestedAttributesSubject.getAttributes() != null) {
            xmlAttestedAttributesSubject.setAttributes(getXmlClaim(attestedAttributesSubject.getAttributes(), claimSupportedClaims));
        }
        xmlAttestedAttributesSubject.getEntry().addAll(getOtherClaims(attestedAttributesSubject, claimSupportedClaims));
        return xmlAttestedAttributesSubject;
    }

    private XmlAttestedAttributesSubjectIdClaim getXmlAttestedAttributesSubjectIdClaim(Claim claim, List<XmlClaim> supportedClaims) {
        if (claim == null) {
            return null;
        }

        if (claim instanceof ClaimAttestedAttributesSubjectId) {
            XmlAttestedAttributesSubjectIdClaim xmlAttestedAttributesSubjectIdClaim = new XmlAttestedAttributesSubjectIdClaim();
            appendGenericInfo(xmlAttestedAttributesSubjectIdClaim, claim, supportedClaims);

            List<XmlClaim> claimSupportedClaims = new ArrayList<>();

            ClaimAttestedAttributesSubjectId attestedAttributesSubjectId = (ClaimAttestedAttributesSubjectId) claim;
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

    private List<XmlClaim> getOtherClaims(Claim claim, List<XmlClaim> supportedClaims) {
        if (claim.isMapValueType() && !claim.isNullOrEmpty()) {
            final List<XmlClaim> otherClaims = new ArrayList<>();
            Collection<String> processedHeaderNames = getHeaderNames(supportedClaims);
            Map<String, Claim> mapValue = claim.getMapValue();
            for (String headerName : mapValue.keySet()) {
                if (!processedHeaderNames.contains(headerName)) {
                    Claim claimValue = mapValue.get(headerName);
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

    private void appendGenericInfo(XmlClaim xmlClaim, Claim claim) {
        appendGenericInfo(xmlClaim, claim, null);
    }

    private void appendGenericInfo(XmlClaim xmlClaim, Claim claim, List<XmlClaim> supportedClaims) {
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

    private List<XmlEAARevocationToken> buildXmlEAARevocationTokens(Collection<AttestationRevocationToken> statusTokens) {
        List<XmlEAARevocationToken> xmlEAARevocationTokens = new ArrayList<>();
        if (Utils.isCollectionNotEmpty(statusTokens)) {
            List<AttestationRevocationToken> tokens = new ArrayList<>(statusTokens);
            tokens.sort(new TokenComparator());
            List<String> uniqueIds = new ArrayList<>(); // possible that EAAs share one EAA Status List
            for (AttestationRevocationToken attestationRevocationToken : tokens) {
                String id = attestationRevocationToken.getDSSIdAsString();
                if (uniqueIds.contains(id)) {
                    continue;
                }
                XmlEAARevocationToken xmlEAARevocationToken = xmlEAARevocationTokenMap.get(id);
                if (xmlEAARevocationToken == null) {
                    xmlEAARevocationToken = buildDetachedXmlEAARevocationToken(attestationRevocationToken);
                    xmlEAARevocationTokenMap.put(id, xmlEAARevocationToken);
                    xmlEAARevocationTokens.add(xmlEAARevocationToken);
                }
                uniqueIds.add(id);
            }
        }
        return xmlEAARevocationTokens;

    }

    /**
     * Builds a new {@code XmlEAARevocationToken}
     *
     * @param attestationRevocationToken {@link AttestationRevocationToken}
     * @return {@link XmlEAARevocationToken}
     */
    protected XmlEAARevocationToken buildDetachedXmlEAARevocationToken(AttestationRevocationToken attestationRevocationToken) {
        final XmlEAARevocationToken xmlEAARevocationToken = new XmlEAARevocationToken();
        xmlEAARevocationToken.setId(identifierProvider.getIdAsString(attestationRevocationToken));
        xmlEAARevocationToken.setOrigin(attestationRevocationToken.getOrigin());
        xmlEAARevocationToken.setType(attestationRevocationToken.getType());
        xmlEAARevocationToken.setSourceAddress(attestationRevocationToken.getSourceURL());
        xmlEAARevocationToken.setSubject(getXmlEAASubject(attestationRevocationToken));
        xmlEAARevocationToken.setIssuedAt(attestationRevocationToken.getCreationDate());
        xmlEAARevocationToken.setExpirationTime(attestationRevocationToken.getExpirationDate());
        if (attestationRevocationToken.getTimeToLive() != null) {
            xmlEAARevocationToken.setTimeToLive(BigInteger.valueOf(attestationRevocationToken.getTimeToLive().longValue()));
        }

        setSignatureInfo(xmlEAARevocationToken, attestationRevocationToken);
        xmlEAARevocationToken.setFoundCertificates(getXmlFoundCertificates(attestationRevocationToken));

        if (tokenExtractionStrategy.isRevocationData()) {
            xmlEAARevocationToken.setBase64Encoded(attestationRevocationToken.getEncoded());
        } else {
            byte[] revocationDigest = attestationRevocationToken.getDigest(defaultDigestAlgorithm);
            xmlEAARevocationToken.setDigestAlgoAndValue(getXmlDigestAlgoAndValue(defaultDigestAlgorithm, revocationDigest));
        }

        return xmlEAARevocationToken;
    }

    private XmlEAASubject getXmlEAASubject(AttestationRevocationToken attestationRevocationToken) {
        if (attestationRevocationToken.getSubject() == null) {
            return null;
        }
        XmlEAASubject xmlEAASubject = new XmlEAASubject();
        xmlEAASubject.setValue(attestationRevocationToken.getSubject());
        if (attestationRevocationToken.getSubjectMatch() != null) {
            xmlEAASubject.setMatch(attestationRevocationToken.getSubjectMatch());
        }
        return xmlEAASubject;
    }

    private void setSignatureInfo(XmlEAARevocationToken xmlEAARevocationToken, AttestationRevocationToken attestationRevocationToken) {
        AdvancedSignature signature = attestationRevocationToken.getSignature();
        if (signature != null) {
            final CandidatesForSigningCertificate candidatesForSigningCertificate = signature.getCandidatesForSigningCertificate();
            final CertificateValidity theCertificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
            PublicKey signingCertificatePublicKey = null;
            if (theCertificateValidity != null) {
                xmlEAARevocationToken.setSigningCertificate(getXmlSigningCertificate(attestationRevocationToken.getDSSId(), theCertificateValidity));
                xmlEAARevocationToken.setCertificateChain(getXmlForCertificateChain(theCertificateValidity, signature.getCertificateSource()));
                signingCertificatePublicKey = theCertificateValidity.getPublicKey();
            }

            xmlEAARevocationToken.setBasicSignature(getXmlBasicSignature(signature, signingCertificatePublicKey));
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

    private void linkEAAAndStatuses(Collection<Attestation> attestations) {
        if (Utils.isCollectionNotEmpty(attestations)) {
            for (Attestation attestation : attestations) {
                XmlEAA xmlEAA = xmlEAAMap.get(attestation.getId());
                Set<AttestationRevocationToken> statusesForEAA = getStatusTokenForEAA(attestation);
                for (AttestationRevocationToken statusToken : statusesForEAA) {
                    XmlEAARevocationToken xmlEAARevocationToken = xmlEAARevocationTokenMap.get(statusToken.getDSSIdAsString());
                    XmlEAARevocationStatus xmlEAARevocationStatus = new XmlEAARevocationStatus();
                    xmlEAARevocationStatus.setEAARevocationToken(xmlEAARevocationToken);
                    xmlEAARevocationStatus.setStatus(statusToken.getStatus());
                    xmlEAA.getEAARevocations().add(xmlEAARevocationStatus);
                }
            }
        }
    }

    private Set<AttestationRevocationToken> getStatusTokenForEAA(Attestation attestation) {
        Set<AttestationRevocationToken> statuses = new HashSet<>();
        if (Utils.isCollectionNotEmpty(attestationRevocationTokens)) {
            for (AttestationRevocationToken attestationRevocationToken : attestationRevocationTokens) {
                if (Utils.areStringsEqual(attestation.getId(), attestationRevocationToken.getRelatedEAAId())) {
                    statuses.add(attestationRevocationToken);
                }
            }
        }
        return statuses;
    }

}
