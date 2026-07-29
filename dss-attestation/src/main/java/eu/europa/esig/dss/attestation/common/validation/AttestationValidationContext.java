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

import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.attestation.AttestationPresentation;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationToken;
import eu.europa.esig.dss.spi.attestation.revocation.AttestationRevocationSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Performs validation of attestation tokens. During validation, retrieved the corresponding information,
 * including the data required for a signature validation, and/or attestation revocation verification.
 */
public class AttestationValidationContext extends SignatureValidationContext {

    private static final Logger LOG = LoggerFactory.getLogger(AttestationValidationContext.class);

    /**
     * Attestation Presentation to process
     */
    private AttestationPresentation processedAttestationPresentation;

    /**
     * A set of AttestationPresentation Status tokens to process
     */
    private final Set<AttestationRevocationToken> processedAttestationRevocationTokens = new LinkedHashSet<>();

    /**
     * Source used to verify revocation of the AttestationPresentation
     */
    private AttestationRevocationSource attestationRevocationSource;

    /**
     * Default constructor instantiating object with null or empty values and current time
     */
    public AttestationValidationContext() {
        this(new Date());
    }

    /**
     * Constructor instantiating object with null or empty values and provided time
     *
     * @param validationTime {@link Date} validation time to be used during the execution
     */
    public AttestationValidationContext(Date validationTime) {
        super(validationTime);
    }

    /**
     * Sets the AttestationRevocationSource used for retrieving an information about a revocation of the AttestationPresentations
     *
     * @param attestationRevocationSource {@link attestationRevocationSource}
     */
    public void setAttestationRevocationSource(AttestationRevocationSource attestationRevocationSource) {
        this.attestationRevocationSource = attestationRevocationSource;
    }

    /**
     * Adds an {@code AttestationPresentation} to be verified
     *
     * @param attestationPresentation {@link AttestationPresentation}
     */
    public void addAttestationPresentationForVerification(final AttestationPresentation attestationPresentation) {
        if (attestationPresentation == null) {
            return;
        }
        if (processedAttestationPresentation != null) {
            throw new IllegalStateException("Attestation Presentation was already added to attestationValidationContext! " +
                    "Only one AttestationPresentation is supported per validation.");
        }

        addAttestationPresentationCertificateSources(attestationPresentation);

        prepareSignatures(attestationPresentation);

        processedAttestationPresentation = attestationPresentation;
        if (LOG.isTraceEnabled()) {
            LOG.trace("AttestationPresentation added to attestationValidationContext");
        }
    }

    private void addAttestationPresentationCertificateSources(AttestationPresentation attestationPresentation) {
        for (Attestation attestation : attestationPresentation.getAttestations()) {
            CertificateSource deviceKeyCertificateSource = attestation.getDeviceKeyCertificateSource();
            if (deviceKeyCertificateSource != null) {
                addDocumentCertificateSource(deviceKeyCertificateSource);
            }
        }
    }

    private void prepareSignatures(AttestationPresentation attestationPresentation) {
        for (Attestation attestation : attestationPresentation.getAttestations()) {
            List<AdvancedSignature> signatures = attestation.getSignatures();
            if (Utils.isCollectionNotEmpty(signatures)) {
                for (AdvancedSignature signature : signatures) {
                    addSignatureForVerification(signature);
                }
            }
            AdvancedSignature keyBindingSignature = attestation.getKeyBindingSignature();
            if (keyBindingSignature != null) {
                addSignatureForVerification(keyBindingSignature);
            }
        }
    }

    /**
     * Adds an {@code AttestationRevocationToken} to be verified
     *
     * @param attestationRevocationToken {@link AttestationRevocationToken}
     */
    public void addAttestationRevocationTokenForVerification(final AttestationRevocationToken attestationRevocationToken) {
        if (attestationRevocationToken == null) {
            return;
        }

        addSignatureForVerification(attestationRevocationToken.getSignature());
        addDocumentCertificateSource(attestationRevocationToken.getCertificateSource());

        final boolean added = processedAttestationRevocationTokens.add(attestationRevocationToken);
        if (LOG.isTraceEnabled()) {
            if (added) {
                LOG.trace("AttestationPresentation Status Token added to processedAttestationRevocationTokens: {} ", attestationRevocationToken.getDSSIdAsString());
            } else {
                LOG.trace("AttestationPresentation already present processedAttestationRevocationTokens: {} ", attestationRevocationToken.getDSSIdAsString());
            }
        }
    }

    @Override
    public void validate() {
        if (processedAttestationPresentation != null) {
            for (Attestation attestation : processedAttestationPresentation.getAttestations()) {
                findAttestationRevocationData(attestation);
            }
        }
        super.validate();
    }

    /**
     * Fetches the AttestationPresentation revocation token for the {@code AttestationPresentation}, when required
     *
     * @param attestation {@link Attestation} to get revocation for
     */
    private void findAttestationRevocationData(Attestation attestation) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Checking revocation data for : {}", attestation.getId());
        }

        if (isAttestationRevocationCheckRequired(attestation)) {
            if (attestationRevocationSource == null) {
                LOG.info("No AttestationRevocationSource has been provided. attestation revocation check is skipped.");
                return;
            }
            if (LOG.isTraceEnabled()) {
                LOG.trace("AttestationPresentation revocation check is in progress for AttestationPresentation : {}", attestation.getId());
            }

            AttestationRevocationToken attestationRevocationToken = attestationRevocationSource.getAttestationRevocation(attestation);
            if (attestationRevocationToken != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Obtained a new AttestationPresentation Status token : {}, for AttestationPresentation : {}",
                            attestationRevocationToken.getDSSIdAsString(), attestation.getId());
                }
                addAttestationRevocationTokenForVerification(attestationRevocationToken);
            }

        } else if (LOG.isDebugEnabled()) {
            LOG.debug("Status data is not required for AttestationPresentation : {}", attestation.getId());
        }
    }

    /**
     * This method verifies whether the {@code AttestationPresentation} requires the revocation verification
     *
     * @param attestation {@link Attestation}
     * @return TRUE if the AttestationPresentation revocation should be checked, FALSE otherwise
     */
    protected boolean isAttestationRevocationCheckRequired(Attestation attestation) {
        if (attestation.getPayload() != null && attestation.getPayload().getShortLived() != null) {
            Boolean shortLived = attestation.getPayload().getShortLived().getBooleanValue();
            return shortLived != null && !Utils.isTrue(shortLived);
        }
        return true;
    }

    /**
     * Gets an AttestationPresentations validated by the context
     *
     * @return {@link AttestationPresentation}
     */
    public AttestationPresentation getProcessedAttestationPresentation() {
        return processedAttestationPresentation;
    }

    /**
     * Gets a set of Attestation Revocation Tokens validated by the context
     *
     * @return a set of {@link AttestationRevocationToken}s
     */
    public Set<AttestationRevocationToken> getProcessedAttestationRevocationTokens() {
        return Collections.unmodifiableSet(processedAttestationRevocationTokens);
    }

    @Override
    public Set<AdvancedSignature> getProcessedSignatures() {
        // exclude attestation revocation signatures
        Set<AdvancedSignature> processedSignatures = super.getProcessedSignatures();
        if (Utils.isCollectionEmpty(processedAttestationRevocationTokens)) {
            return processedSignatures;
        }
        final Set<AdvancedSignature> result = new HashSet<>();
        for (AdvancedSignature advancedSignature : processedSignatures) {
            if (processedAttestationRevocationTokens.stream().noneMatch(t -> t.getSignature() != null
                    && advancedSignature.getId().equals(t.getSignature().getId()))) {
                result.add(advancedSignature);
            }
        }
        return result;
    }

}
