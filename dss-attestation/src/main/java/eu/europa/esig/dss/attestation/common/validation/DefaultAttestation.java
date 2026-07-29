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

import eu.europa.esig.dss.attestation.common.validation.identifier.AttestationIdentifierBuilder;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.attestation.SelectivelyDisclosableClaim;
import eu.europa.esig.dss.model.attestation.DisclosureValidation;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDeviceKey;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.attestation.AttestationPayload;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.ProofOfPossessionCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Abstract implementation of an attestation
 *
 */
public abstract class DefaultAttestation implements Attestation {

    /** Cached signature objects used to create the attestation */
    private List<AdvancedSignature> signatures;

    /** List of disclosures attached to the Attestation Presentation */
    private List<SelectivelyDisclosableClaim> disclosures;

    /** Key binding signature (optional) */
    private AdvancedSignature keyBindingSignature;

    /** The name of the attestation document */
    private String filename;

    /** Unique attestation identifier */
    private Identifier identifier;

    /** Cached instance of an attestation Payload Verifier */
    private AttestationPayloadVerifier attestationPayloadVerifier;

    /**
     * Default constructor
     */
    protected DefaultAttestation() {
        // empty
    }

    @Override
    public String getFilename() {
        return filename;
    }

    @Override
    public List<AdvancedSignature> getSignatures() {
        return signatures;
    }

    /**
     * Gets a list of disclosures
     *
     * @return a list of {@link SelectivelyDisclosableClaim}s
     */
    public List<SelectivelyDisclosableClaim> getDisclosures() {
        return disclosures;
    }

    @Override
    public List<DisclosureValidation> getDisclosureValidations() {
        return getAttestationPayloadVerifier().getDisclosureValidations();
    }

    @Override
    public AdvancedSignature getKeyBindingSignature() {
        return keyBindingSignature;
    }

    @Override
    public AttestationPayload getPayload() {
        return getAttestationPayloadVerifier().getVerifiedPayload();
    }

    /**
     * Gets the attestation Payload Verifier, performing a verification of the attached disclosures as well as
     * building a constructed version of the attestation Payload with the discloses values attached
     *
     * @return {@link AttestationPayloadVerifier}
     */
    protected AttestationPayloadVerifier getAttestationPayloadVerifier() {
        if (attestationPayloadVerifier == null) {
            attestationPayloadVerifier = initAttestationPayloadVerifier().setDisclosures(disclosures);
            attestationPayloadVerifier.verify();
        }
        return attestationPayloadVerifier;
    }

    /**
     * Creates a new instance of {@code AttestationPayloadVerifier} relatively to the current implementation
     *
     * @return {@link AttestationPayloadVerifier}
     */
    protected abstract AttestationPayloadVerifier initAttestationPayloadVerifier();

    @Override
    public DigestAlgorithm getSelectiveDisclosuresDigestAlgorithm() {
        return getAttestationPayloadVerifier().getDigestAlgorithm();
    }

    @Override
    public CertificateSource getDeviceKeyCertificateSource() {
        AdvancedSignature kbSignature = getKeyBindingSignature();
        if (kbSignature != null) {
            return getProofOfPossessionCertificateSource(kbSignature.getSigningCertificateSource());
        }
        return null;
    }

    private CertificateSource getProofOfPossessionCertificateSource(CertificateSource certificateSource) {
        if (certificateSource instanceof ProofOfPossessionCertificateSource) {
            return certificateSource;
        } else if (certificateSource instanceof ListCertificateSource) {
            for (CertificateSource embeddedCertSource : ((ListCertificateSource) certificateSource).getSources()) {
                CertificateSource popCertificateSource = getProofOfPossessionCertificateSource(embeddedCertSource);
                if (popCertificateSource != null) {
                    return popCertificateSource;
                }
            }
        }
        return null;
    }

    @Override
    public String getId() {
        return getDSSId().asXmlId();
    }

    @Override
    public Identifier getDSSId() {
        if (identifier == null) {
            identifier = new AttestationIdentifierBuilder().build(this);
        }
        return identifier;
    }

    /**
     * This class is used to build a DefaultAttestation
     *
     */
    protected static abstract class DefaultAttestationBuilder {

        private static final Logger LOG = LoggerFactory.getLogger(DefaultAttestationBuilder.class);

        /** Cached signature objects used to create the attestation */
        private List<AdvancedSignature> signatures;

        /** List of disclosures attached to the Attestation Presentation */
        private List<SelectivelyDisclosableClaim> disclosures;

        /** Key binding signature (optional) */
        private AdvancedSignature keyBindingSignature;

        /** The name of the attestation document */
        private String filename;

        /**
         * Default constructor
         */
        public DefaultAttestationBuilder() {
            // empty
        }

        /**
         * Sets signatures list used to create the attestation
         *
         * @param signatures a list of {@link AdvancedSignature}s
         * @return this builder
         */
        public DefaultAttestationBuilder setSignatures(List<AdvancedSignature> signatures) {
            this.signatures = signatures;
            return this;
        }

        /**
         * Sets a list of disclosures provided with the SD-JWT token
         *
         * @param disclosures a list of {@link SelectivelyDisclosableClaim}s
         * @return this builder
         */
        public DefaultAttestationBuilder setDisclosures(List<SelectivelyDisclosableClaim> disclosures) {
            this.disclosures = disclosures;
            return this;
        }

        /**
         * Sets the key binding signature, when present
         *
         * @param keyBindingSignature {@link AdvancedSignature}
         * @return this builder
         */
        public DefaultAttestationBuilder setKeyBindingSignature(AdvancedSignature keyBindingSignature) {
            this.keyBindingSignature = keyBindingSignature;
            return this;
        }

        /**
         * Sets the document filename
         *
         * @param filename {@link String}
         * @return this builder
         */
        public DefaultAttestationBuilder setFilename(String filename) {
            this.filename = filename;
            return this;
        }

        /**
         * Builds a new attestation object
         *
         * @return {@link DefaultAttestation}
         */
        public DefaultAttestation build() {
            if (Utils.isCollectionEmpty(signatures)) {
                throw new NullPointerException("Signatures list cannot be null or empty!");
            }
            DefaultAttestation attestation = initAttestation();
            attestation.signatures = signatures;
            for (AdvancedSignature signature : signatures) {
                signature.setAttestation(attestation);
            }
            attestation.disclosures = disclosures;
            if (keyBindingSignature != null) {
                CertificateSource signingCertificateSource = new ListCertificateSource(
                        getHolderCertificateSource(attestation.getPayload()), getSigningCertificateSource(signatures));
                keyBindingSignature.setSigningCertificateSource(signingCertificateSource);
                attestation.keyBindingSignature = keyBindingSignature;
                keyBindingSignature.setAttestation(attestation);
                keyBindingSignature.setKeyBindingSignature(true);
            }
            attestation.filename = filename;
            return attestation;
        }

        /**
         * Gets a certificate source containing a key of the attestation holder
         *
         * @param attestationPayload {@link AttestationPayload}
         * @return {@link CertificateSource}
         */
        protected CertificateSource getHolderCertificateSource(AttestationPayload attestationPayload) {
            VerifiedClaimDeviceKey claimDeviceKey = attestationPayload.getDeviceKey();
            if (claimDeviceKey != null) {
                try {
                    return new DeviceKeyClaimCertificateSource(claimDeviceKey);
                } catch (Exception e) {
                    LOG.warn("Unable to read the device key claim : {}", e.getMessage(), e);
                }
            }
            return null;
        }

        private CertificateSource getSigningCertificateSource(List<AdvancedSignature> signatures) {
            AdvancedSignature signature = signatures.get(0);
            return signature.getSigningCertificateSource();
        }

        /**
         * Instantiates a new {@code DefaultAttestation} object
         *
         * @return {@link DefaultAttestation}
         */
        protected abstract DefaultAttestation initAttestation();

    }

}
