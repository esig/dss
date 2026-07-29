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
import java.util.List;

/**
 * This interface {@link AttestationService} provides operations for the issuance of attestations (EAA, PID, etc.).
 * This service provides the following functionalities:
 * - Signing and issuance of attestations;
 * - Generation and extraction of selectively disclosable claims;
 * - Generation of key binding (device binding) signature;
 * - Issuance of Attestation Presentation.
 *
 * @param <SP>
 *         implementation of signature parameters corresponding to the supported signature format
 * @param <B>
 *         implementation of attestation payload parameters to the attestation format
 * @param <D>
 *         implementation of attestation disclosure for the attestation format
 * @param <E>
 *         implementation of attestation key binding parameters for the attestation format
 */
public interface AttestationService<SP extends SerializableSignatureParameters, B extends AttestationPayloadParameters, D extends SelectiveDisclosure, E extends KeyBindingParameters> extends Serializable {

    /**
     * Prepares binaries to be used on computation of a signature value, format specific.
     * This method takes a pre-computed payload as a parameter.
     *
     * @param payload
     *            {@link DSSDocument} the payload to sign
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} set of the driving signing parameters
     * @return {@link ToBeSigned}
     */
    ToBeSigned getDataToBeSigned(DSSDocument payload, SP signatureParameters);

    /**
     * Prepares binaries to be used on computation of a signature value, format specific.
     * This method takes a configuration of payload parameters and computes a resulting payload based on it.
     *
     * @param payloadParameters
     *            {@link AttestationPayloadParameters} the payload parameters
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} set of thedriving signing parameters
     * @return {@link ToBeSigned}
     */
    ToBeSigned getDataToBeSigned(B payloadParameters, SP signatureParameters);

    /**
     * Signs an attestation with the provided signatureValue.
     * This method takes a pre-computed payload as a parameter.
     *
     * @param payload
     *            {@link DSSDocument} the payload to sign
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} set of the driving signing parameters
     * @param signatureValue
     *            {@link SignatureValue} the signature value to incorporate
     * @return {@link DSSDocument} the signed attestation
     */
    DSSDocument signAttestation(DSSDocument payload, SP signatureParameters, SignatureValue signatureValue);

    /**
     * Signs the payload with the provided signatureValue.
     * This method takes a configuration of payload parameters and computes a resulting payload based on it.
     *
     * @param payloadParameters
     *            {@link AttestationPayloadParameters} the payload parameters
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} set of the driving signing parameters
     * @param signatureValue
     *            {@link SignatureValue} the signature value to incorporate
     * @return {@link DSSDocument} the signed attestation
     */
    DSSDocument signAttestation(B payloadParameters, SP signatureParameters, SignatureValue signatureValue);

    /**
     * Gets a list of disclosures for all selectively disclosable claims defined within the parameters
     *
     * @param payloadParameters {@link AttestationPayloadParameters} the payload parameters
     * @return a list of {@link SelectiveDisclosure}s
     */
    List<D> getDisclosures(final B payloadParameters);

    /**
     * Created a DataToBeSigned (DTBS) for a key-binding signature creation, format specific.
     * This method can be used when no disclosures are to be provided within the final Attestation Presentation.
     *
     * @param attestation
     *            {@link DSSDocument} representing a signed attestation
     * @param keyBindingParameters
     *            {@link KeyBindingParameters} key binding signature configuration
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} set of the driving signing parameters
     * @return {@link ToBeSigned}
     */
    ToBeSigned getDataToSignForKeyBindingSignature(DSSDocument attestation, E keyBindingParameters, SP signatureParameters);

    /**
     * Created a DataToBeSigned (DTBS) for a key-binding signature creation, format specific.
     * This method can be used when selective disclosures are to be provided within the final Attestation Presentation.
     *
     * @param attestation
     *            {@link DSSDocument} representing a signed attestation
     * @param disclosures
     *            a list of {@link SelectiveDisclosure}s to be provided with the attestation presentation
     * @param keyBindingParameters
     *            {@link KeyBindingParameters} key binding signature configuration
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} set of the driving signing parameters
     * @return {@link ToBeSigned}
     */
    ToBeSigned getDataToSignForKeyBindingSignature(DSSDocument attestation, List<D> disclosures, E keyBindingParameters, SP signatureParameters);

    /**
     * Creates a key-binding signature, format specific.
     * This method can be used when no disclosures are to be provided within the final Attestation Presentation.
     *
     * @param attestation
     * @param keyBindingParameters
     *            {@link KeyBindingParameters} key binding signature configuration
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} set of the driving signing parameters
     * @param signatureValue
     *            {@link SignatureValue}
     * @return {@link ToBeSigned}
     */
    DSSDocument createKeyBindingSignature(DSSDocument attestation, E keyBindingParameters, SP signatureParameters, SignatureValue signatureValue);

    /**
     * Creates a key-binding signature, format specific.
     * This method can be used when selective disclosures are to be provided within the final Attestation Presentation.
     *
     * @param attestation
     *            {@link DSSDocument} representing a signed attestation
     * @param disclosures
     *            a list of {@link SelectiveDisclosure}s to be provided with the attestation presentation
     * @param keyBindingParameters
     *            {@link KeyBindingParameters} key binding signature configuration
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} set of the driving signing parameters
     * @param signatureValue
     *            {@link SignatureValue}
     * @return {@link ToBeSigned}
     */
    DSSDocument createKeyBindingSignature(DSSDocument attestation, List<D> disclosures, E keyBindingParameters, SP signatureParameters, SignatureValue signatureValue);

    /**
     * Creates an Attestation Presentation, with provided selective disclosures and no key binding signature
     *
     * @param attestation
     *            {@link DSSDocument} representing a signed attestation
     * @param disclosures
     *            a list of {@link SelectiveDisclosure}s to be provided with the attestation presentation
     * @return {@link DSSDocument} Attestation Presentation
     */
    DSSDocument issuePresentation(DSSDocument attestation, List<D> disclosures);

    /**
     * Creates an Attestation Presentation, with no selective disclosures and provided key binding signature
     *
     * @param attestation
     *            {@link DSSDocument} representing a signed attestation
     * @param keyBinding
     *            {@link DSSDocument} representing a key binding signature
     * @return {@link DSSDocument} Attestation Presentation
     */
    DSSDocument issuePresentation(DSSDocument attestation, DSSDocument keyBinding);

    /**
     * Creates an Attestation Presentation, with provided selective disclosures and key binding signature
     *
     * @param attestation
     *            {@link DSSDocument} representing a signed attestation
     * @param disclosures
     *            a list of {@link SelectiveDisclosure}s to be provided with the attestation presentation
     * @param keyBinding
     *            {@link DSSDocument} representing a key binding signature
     * @return {@link DSSDocument} Attestation Presentation
     */
    DSSDocument issuePresentation(DSSDocument attestation, List<D> disclosures, DSSDocument keyBinding);

}
