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
package eu.europa.esig.dss.ws.attestation.creation.common;

import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.io.Serializable;

/**
 * Remote service to sign an attestation (e.g. EAA, PID, etc.)
 *
 */
public interface RemoteAttestationCreationService extends Serializable {

    /**
     * Retrieves the bytes of the data that need to be signed based on the {@code payload} and {@code parameters}.
     *
     * @param payloadParameters
     *            parameters containing configuration for the payload generation
     * @param signatureParameters
     *            set of the driving signing parameters
     * @return the data to be signed
     */
    ToBeSignedDTO getDataToSign(final RemoteAttestationPayloadParameters payloadParameters,
                                final RemoteSignatureParameters signatureParameters);

    /**
     * Signs the payload with the provided signatureValue.
     *
     * @param payloadParameters
     *            parameters containing configuration for the payload generation
     * @param signatureParameters
     *            set of the driving signing parameters
     * @param signatureValue
     *            the signature value to incorporate
     * @return the signed document (signature signing the {@code payload})
     */
    RemoteDocument signAttestation(final RemoteAttestationPayloadParameters payloadParameters, final RemoteSignatureParameters signatureParameters,
                           final SignatureValueDTO signatureValue);

}
