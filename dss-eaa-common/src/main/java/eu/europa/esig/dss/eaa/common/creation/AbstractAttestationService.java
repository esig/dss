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
package eu.europa.esig.dss.eaa.common.creation;

import eu.europa.esig.dss.eaa.common.creation.claim.AttestationClaim;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.SigningOperation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.spi.signature.FileNameBuilder;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

import java.util.Objects;

/**
 * Abstract implementation of an EAA creation service.
 *
 * @param <SP>
 *         implementation of signature parameters corresponding to the supported signature format
 * @param <B>
 *         implementation of EAA payload parameters to the EAA format
 * @param <C>
 *         implementation of EAA Claim for the EAA format
 * @param <D>
 *         implementation of EAA disclosure for the EAA format
 * @param <E>
 *         implementation of EAA key binding parameters for the EAA format
 */
public abstract class AbstractAttestationService<SP extends SerializableSignatureParameters, B extends AttestationPayloadParameters, C extends AttestationClaim, D extends SelectiveDisclosure, E extends KeyBindingParameters> implements AttestationService<SP, B, D, E> {

    private static final long serialVersionUID = -8272997238108493534L;

    /** CertificateVerifier used to provide configuration on the validation of the signing certificate and its chain */
    protected final CertificateVerifier certificateVerifier;

    /** Builds the EAA payload */
    protected AttestationPayloadBuilder<B, D> payloadBuilder;

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     */
    protected AbstractAttestationService(final CertificateVerifier certificateVerifier) {
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier cannot be null !");
        this.certificateVerifier = certificateVerifier;
    }

    /**
     * Gets the payload builder. If not set, instantiates a default value (format specific)
     *
     * @return {@link AttestationPayloadBuilder}
     */
    protected AttestationPayloadBuilder<B, D> getPayloadBuilder() {
        if (payloadBuilder == null) {
            payloadBuilder = initDefaultPayloadBuilder();
        }
        return payloadBuilder;
    }

    /**
     * Instantiates a default {@code EAAPayloadBuilder} implementation
     *
     * @return {@link AttestationPayloadBuilder}
     */
    protected abstract AttestationPayloadBuilder<B, D> initDefaultPayloadBuilder();

    /**
     * Sets the builder used to create an EAA Payload based on the input parameters.
     * Default : provided format specific implementation is used by default
     *
     * @param payloadBuilder {@link AttestationPayloadBuilder}
     */
    public void setPayloadBuilder(AttestationPayloadBuilder<B, D> payloadBuilder) {
        Objects.requireNonNull(payloadBuilder, "EAAPayloadBuilder cannot be null!");
        this.payloadBuilder = payloadBuilder;
    }

    /**
     * Gets the final document name when original document is present
     *
     * @param originalFile {@link DSSDocument} original document
     * @return {@link String}
     */
    protected String getFinalDocumentName(DSSDocument originalFile) {
        return getFinalDocumentNameBuilder().setOriginalFilename(originalFile.getName()).build();
    }

    /**
     * Gets the final document name when original document is present
     *
     * @return {@link String}
     */
    protected FileNameBuilder getFinalDocumentNameBuilder() {
        return new FileNameBuilder().setSigningOperation(SigningOperation.EAA_PRESENTATION).setMimeType(getEAAPresentationMimeType());
    }

    /**
     * Gets the MimeType of the Attestation Presentation for the given EAA format
     *
     * @return {@link MimeType}
     */
    protected abstract MimeType getEAAPresentationMimeType();

}
