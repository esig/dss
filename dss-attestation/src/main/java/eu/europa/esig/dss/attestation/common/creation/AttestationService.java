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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;

import java.io.Serializable;

/**
 * Service for creating and signing digital attestations (for example, EAA, PID,
 * or other supported attestation formats).
 * <p>
 * This service is primarily intended to be used by an attestation issuer
 * during the attestation issuance process. It is responsible for preparing the
 * attestation payload for signing and embedding an externally computed
 * signature into the final signed attestation.
 * <p>
 * The service supports two workflows:
 * <ul>
 *   <li>using an already constructed attestation payload; or</li>
 *   <li>generating the payload from {@link AttestationPayloadParameters}.</li>
 * </ul>
 * <p>
 * The signing process follows a three-step signature model:
 * <ol>
 *   <li>Create the format-specific Data To Be Signed (DTBS).</li>
 *   <li>Compute the signature using an external signing component, HSM, or
 *       remote signing service.</li>
 *   <li>Create the attestation signature embedding the payload.</li>
 * </ol>
 * <p>
 * This service produces an attestation signature that may subsequently be
 * issued directly or enriched with selective disclosures.
 *
 * @param <SP>
 *           implementation of the signature parameters for the supported signature format
 * @param <B>
 *           implementation of the attestation payload parameters for the supported attestation format
 */
public interface AttestationService<SP extends SerializableSignatureParameters, B extends AttestationPayloadParameters> extends Serializable {

    /**
     * Creates the format-specific data to be signed (DTBS) from an existing
     * attestation payload.
     * <p>
     * This method is intended for workflows where the payload has already been
     * constructed and only the signing data must be generated.
     *
     * @param payload
     *             {@link DSSDocument} precomputed attestation payload
     * @param signatureParameters
     *             {@link SerializableSignatureParameters} signature configuration
     * @return {@link ToBeSigned} the bytes that must be signed by the signing key
     */
    ToBeSigned getDataToSign(DSSDocument payload, SP signatureParameters);

    /**
     * Creates the format-specific data to be signed (DTBS) from a payload
     * definition.
     * <p>
     * The implementation generates the attestation payload from the supplied
     * payload parameters before computing the data to be signed.
     *
     * @param payloadParameters
     *             {@link AttestationPayloadParameters} parameters describing the attestation payload
     * @param signatureParameters
     *             {@link SerializableSignatureParameters} signature configuration
     * @return the bytes that must be signed by the signing key
     */
    ToBeSigned getDataToSign(B payloadParameters, SP signatureParameters);

    /**
     * Produces a signed attestation by embedding the provided signature value into
     * an existing payload.
     * <p>
     * The signature value is expected to sign the DTBS previously
     * obtained through {@link #getDataToSign(DSSDocument, SerializableSignatureParameters)}.
     *
     * @param payload
     *            {@link DSSDocument} precomputed attestation payload
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} signature configuration
     * @param signatureValue
     *            {@link SignatureValue} signature computed over the DTBS
     * @return {@link DSSDocument} the signed attestation
     */
    DSSDocument signAttestation(DSSDocument payload, SP signatureParameters, SignatureValue signatureValue);

    /**
     * Generates an attestation payload from the supplied parameters and embeds the
     * provided signature value into the resulting attestation.
     * <p>
     * The signature value is expected to sign the DTBS previously
     * obtained through {@link #getDataToSign(AttestationPayloadParameters, SerializableSignatureParameters)}.
     *
     * @param payloadParameters
     *            {@link AttestationPayloadParameters} parameters describing the attestation payload
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} signature configuration
     * @param signatureValue
     *            {@link SignatureValue} signature computed over the DTBS
     * @return {@link DSSDocument} the signed attestation
     */
    DSSDocument signAttestation(B payloadParameters, SP signatureParameters, SignatureValue signatureValue);

}
