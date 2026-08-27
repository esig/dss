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
package eu.europa.esig.dss.attestation.common.creation;

import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

/**
 * Abstract implementation of an attestation with selective disclosures creation service.
 *
 * @param <SP>
 *         implementation of attestation Claim for the attestation format
 * @param <P>
 *         implementation of attestation payload parameters to the attestation format
 * @param <D>
 *         implementation of attestation disclosure for the attestation format
 */
public abstract class AbstractAttestationSDService<SP extends SerializableSignatureParameters, P extends AttestationPayloadParameters,
        D extends SelectiveDisclosure> extends AbstractAttestationService<SP, P, AttestationSDPayloadBuilder<P, D>>
        implements AttestationSDService<SP, P, D> {

    private static final long serialVersionUID = -1605530972695706489L;

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     */
    protected AbstractAttestationSDService(CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
    }

}
