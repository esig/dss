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
package eu.europa.esig.dss.ws.attestation.creation.common.builder;

import eu.europa.esig.dss.cbades.signature.CBAdESCounterSignatureParameters;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.AttestationFormat;
import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteBLevelParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Builds {@code SerializableSignatureParameters} from {@link RemoteSignatureParameters}
 *
 */
public class RemoteAttestationCreationSignatureParametersBuilder {

    /** Type of the EAA */
    private final AttestationFormat attestationFormat;

    /** DTO representing the signature parameters */
    private final RemoteSignatureParameters remoteSignatureParameters;

    /**
     * Default constructor
     *
     * @param attestationFormat {@link AttestationFormat}
     * @param remoteSignatureParameters {@link RemoteSignatureParameters}
     */
    public RemoteAttestationCreationSignatureParametersBuilder(final AttestationFormat attestationFormat, final RemoteSignatureParameters remoteSignatureParameters) {
        this.attestationFormat = attestationFormat;
        this.remoteSignatureParameters = remoteSignatureParameters;
    }

    /**
     * Builds the {@code SerializableSignatureParameters}
     *
     * @return {@link SerializableSignatureParameters}
     */
    public SerializableSignatureParameters build() {
        SerializableSignatureParameters parameters = getSignatureParameters(remoteSignatureParameters);
        fillParameters(parameters, remoteSignatureParameters);
        return parameters;
    }

    /**
     * Creates parameters for a signature creation (not container)
     *
     * @param remoteParameters {@link RemoteSignatureParameters}
     * @return {@link SerializableSignatureParameters}
     */
    protected SerializableSignatureParameters getSignatureParameters(RemoteSignatureParameters remoteParameters) {
        switch (attestationFormat) {
            case SD_JWT_VC:
                return getJAdESSignatureParameters(remoteParameters);
            case ISO_IEC_MDOC:
                return getCBAdESSignatureParameters(remoteParameters);
            default:
                throw new UnsupportedOperationException(String.format("Unsupported EAA type : %s", attestationFormat));
        }
    }

    /**
     * Return {@code JAdESSignatureParameters} in order to support JAdES signature
     *
     * @param remoteParameters {@link RemoteSignatureParameters}
     * @return {@link JAdESSignatureParameters}
     */
    protected JAdESSignatureParameters getJAdESSignatureParameters(RemoteSignatureParameters remoteParameters) {
        JAdESSignatureParameters jadesParameters = new JAdESSignatureParameters();
        if (remoteParameters.getJwsSerializationType() != null) {
            jadesParameters.setJwsSerializationType(remoteParameters.getJwsSerializationType());
        }
        if (remoteParameters.getSigDMechanism() != null) {
            jadesParameters.setSigDMechanism(remoteParameters.getSigDMechanism());
        }
        if (remoteParameters.isBase64UrlEncodedPayload() != null) {
            jadesParameters.setBase64UrlEncodedPayload(remoteParameters.isBase64UrlEncodedPayload());
        }
        if (remoteParameters.isBase64UrlEncodedEtsiUComponents() != null) {
            jadesParameters.setBase64UrlEncodedEtsiUComponents(remoteParameters.isBase64UrlEncodedEtsiUComponents());
        }
        if (remoteParameters.getSignatureType() != null) {
            jadesParameters.setSignatureType(remoteParameters.getSignatureType());
        }
        if (remoteParameters.getKeyIdentifier() != null) {
            jadesParameters.setKeyIdentifier(remoteParameters.getKeyIdentifier());
        }
        if (remoteParameters.getX509Url() != null) {
            jadesParameters.setX509Url(remoteParameters.getX509Url());
        }
        return jadesParameters;
    }

    /**
     * Return {@code CBAdESSignatureParameters} in order to support CB-AdES signature
     *
     * @param remoteParameters {@link RemoteSignatureParameters}
     * @return {@link CBAdESSignatureParameters}
     */
    protected CBAdESSignatureParameters getCBAdESSignatureParameters(RemoteSignatureParameters remoteParameters) {
        CBAdESSignatureParameters cbadesParameters = new CBAdESCounterSignatureParameters();
        if (remoteParameters.getCoseStructureType() != null) {
            cbadesParameters.setCoseStructureType(remoteParameters.getCoseStructureType());
        }
        if (remoteParameters.getTagged() != null) {
            cbadesParameters.setTagged(remoteParameters.getTagged());
        }
        if (remoteParameters.getExternallySuppliedData() != null) {
            cbadesParameters.setExternallySuppliedData(RemoteDocumentConverter.toDSSDocument(remoteParameters.getExternallySuppliedData()));
        }
        if (remoteParameters.getSigDMechanism() != null) {
            cbadesParameters.setSigDMechanism(remoteParameters.getSigDMechanism());
        }
        if (remoteParameters.getSignatureType() != null) {
            cbadesParameters.setSignatureType(remoteParameters.getSignatureType());
        }
        if (remoteParameters.getKeyIdentifier() != null) {
            cbadesParameters.setKeyIdentifier(remoteParameters.getKeyIdentifier().getBytes());
        }
        if (remoteParameters.getX509Url() != null) {
            cbadesParameters.setX509Url(remoteParameters.getX509Url());
        }
        return cbadesParameters;
    }

    /**
     * Fills the parameters
     *
     * @param signatureParameters {@link SerializableSignatureParameters} to fill
     * @param remoteParameters {@link RemoteSignatureParameters} to get values from
     */
    @SuppressWarnings("unchecked")
    protected void fillParameters(SerializableSignatureParameters signatureParameters,
                                  RemoteSignatureParameters remoteParameters) {
        if (!(signatureParameters instanceof AbstractSignatureParameters<?>)) {
            return;
        }

        AbstractSignatureParameters<TimestampParameters> parameters =
                (AbstractSignatureParameters<TimestampParameters>) signatureParameters;
        // certificate shall be provided first
        RemoteCertificate signingCertificate = remoteParameters.getSigningCertificate();
        if (signingCertificate != null) { // extends do not require signing certificate
            CertificateToken certificateToken = RemoteCertificateConverter.toCertificateToken(signingCertificate);
            parameters.setSigningCertificate(certificateToken);
        }

        List<RemoteCertificate> remoteCertificateChain = remoteParameters.getCertificateChain();
        if (Utils.isCollectionNotEmpty(remoteCertificateChain)) {
            parameters.setCertificateChain(RemoteCertificateConverter.toCertificateTokens(remoteCertificateChain));
        }

        parameters.setBLevelParams(toBLevelParameters(remoteParameters.getBLevelParams()));
        parameters.setDetachedContents(RemoteDocumentConverter.toDSSDocuments(remoteParameters.getDetachedContents()));

        if (remoteParameters.getDigestAlgorithm() != null) {
            parameters.setDigestAlgorithm(remoteParameters.getDigestAlgorithm());
        }
        if (remoteParameters.getEncryptionAlgorithm() != null) {
            parameters.setEncryptionAlgorithm(remoteParameters.getEncryptionAlgorithm());
        }
        if (remoteParameters.getReferenceDigestAlgorithm() != null) {
            parameters.setReferenceDigestAlgorithm(remoteParameters.getReferenceDigestAlgorithm());
        }

        if (remoteParameters.getSignatureLevel() != null) {
            parameters.setSignatureLevel(remoteParameters.getSignatureLevel());
        }
        if (remoteParameters.getSignaturePackaging() != null) {
            parameters.setSignaturePackaging(remoteParameters.getSignaturePackaging());
        }
        parameters.setGenerateTBSWithoutCertificate(remoteParameters.isGenerateTBSWithoutCertificate());
    }

    /**
     * Converts {@code RemoteBLevelParameters} to {@code BLevelParameters}
     *
     * @param remoteBLevelParameters {@link RemoteBLevelParameters}
     * @return {@link BLevelParameters}
     */
    protected BLevelParameters toBLevelParameters(RemoteBLevelParameters remoteBLevelParameters) {
        BLevelParameters bLevelParameters = new BLevelParameters();
        bLevelParameters.setClaimedSignerRoles(remoteBLevelParameters.getClaimedSignerRoles());
        bLevelParameters.setSignedAssertions(remoteBLevelParameters.getSignedAssertions());
        if (remoteBLevelParameters.getCommitmentTypeIndications() != null) {
            bLevelParameters.setCommitmentTypeIndications(toCommitmentTypeList(remoteBLevelParameters.getCommitmentTypeIndications()));
        }
        if (remoteBLevelParameters.getSigningDate() != null) {
            bLevelParameters.setSigningDate(remoteBLevelParameters.getSigningDate());
        }
        bLevelParameters.setTrustAnchorBPPolicy(remoteBLevelParameters.isTrustAnchorBPPolicy());

        Policy policy = new Policy();
        policy.setDescription(remoteBLevelParameters.getPolicyDescription());
        policy.setDigestAlgorithm(remoteBLevelParameters.getPolicyDigestAlgorithm());
        policy.setDigestValue(remoteBLevelParameters.getPolicyDigestValue());
        policy.setId(remoteBLevelParameters.getPolicyId());
        policy.setQualifier(remoteBLevelParameters.getPolicyQualifier());
        policy.setSpuri(remoteBLevelParameters.getPolicySpuri());
        if (!policy.isEmpty()) {
            bLevelParameters.setSignaturePolicy(policy);
        }

        SignerLocation signerLocation = new SignerLocation();
        signerLocation.setCountry(remoteBLevelParameters.getSignerLocationCountry());
        signerLocation.setLocality(remoteBLevelParameters.getSignerLocationLocality());
        signerLocation.setPostalAddress(remoteBLevelParameters.getSignerLocationPostalAddress());
        signerLocation.setPostalCode(remoteBLevelParameters.getSignerLocationPostalCode());
        signerLocation.setStateOrProvince(remoteBLevelParameters.getSignerLocationStateOrProvince());
        signerLocation.setStreetAddress(remoteBLevelParameters.getSignerLocationStreet());
        if (!signerLocation.isEmpty()) {
            bLevelParameters.setSignerLocation(signerLocation);
        }

        return bLevelParameters;
    }

    /**
     * Transforms a list of {@code CommitmentTypeEnum}s to a list of {@code CommitmentType}s
     *
     * @param commitmentTypeEnums a list of {@link CommitmentTypeEnum}s
     * @return a list of {@link CommitmentType}s
     */
    protected List<CommitmentType> toCommitmentTypeList(List<CommitmentTypeEnum> commitmentTypeEnums) {
        if (Utils.isCollectionNotEmpty(commitmentTypeEnums)) {
            return commitmentTypeEnums.stream().map(CommitmentType.class::cast).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

}
