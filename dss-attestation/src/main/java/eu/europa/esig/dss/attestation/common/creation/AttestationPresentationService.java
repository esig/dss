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
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;

import java.io.Serializable;
import java.util.List;

/**
 * Service for creating attestation presentations from previously issued
 * attestations.
 * <p>
 * This service is primarily intended to be used by a wallet or another
 * holder-controlled application after receiving an issued attestation from an
 * issuer. It enables the holder to construct an attestation presentation by
 * selecting which disclosures to reveal and, if required by the attestation
 * format, creating a holder key-binding signature.
 * <p>
 * The typical workflow is:
 * <ol>
 *   <li>Parse the received attestation to implementation supported objects.</li>
 *   <li>Select the disclosures to be revealed.</li>
 *   <li>Create the Data To Be Signed (DTBS) for the holder key-binding signature.</li>
 *   <li>Generate the key-binding signature using the wallet's or holder's private key.</li>
 *   <li>Assemble the final attestation presentation.</li>
 * </ol>
 * <p>
 * The resulting presentation is intended to be shared with a verifier,
 * allowing verification of both the issuer's signature, selective disclosures and,
 * when applicable, the holder's proof of possession of the bound key.
 *
 * @param <SP>
 *         implementation of the signature parameters
 * @param <D>
 *         implementation of the selective disclosure representation
 * @param <E>
 *         implementation of the key-binding parameters
 */
public interface AttestationPresentationService<SP extends SerializableSignatureParameters,
        D extends SelectiveDisclosure, E extends KeyBindingParameters> extends Serializable {

    /**
     * Parses an issued attestation into its logical components.
     * <p>
     * This method is typically invoked by a wallet instance after receiving an
     * attestation from an issuer. The returned object contains the signed
     * attestation together with all available disclosures, allowing the wallet to
     * choose which claims will be presented.
     *
     * @param attestation
     *             {@link DSSDocument} issued attestation
     * @return {@link AttestationDocument}
     */
    AttestationDocument<D> parseAttestation(DSSDocument attestation);

    /**
     * Creates the format-specific data to be signed by a device key for
     * a key-binding signature.
     * <p>
     * The resulting DTBS covers the signed attestation and binds it to the
     * holder according to the supplied key-binding parameters.
     *
     * @param signedAttestation
     *            {@link DSSDocument} signed attestation
     * @param keyBindingParameters
     *            {@link KeyBindingParameters} key-binding configuration
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} signature configuration
     * @return {@link ToBeSigned} the bytes that must be signed by the device key
     */
    ToBeSigned getDataToSignForKeyBindingSignature(DSSDocument signedAttestation, E keyBindingParameters, SP signatureParameters);

    /**
     * Creates the format-specific data to be signed by a device key for
     * a key-binding signature covering the supplied disclosures.
     *
     * @param signedAttestation
     *            {@link DSSDocument} signed attestation
     * @param disclosures
     *            a list of {@link SelectiveDisclosure}s to be included in the presentation
     * @param keyBindingParameters
     *            {@link KeyBindingParameters} key binding signature configuration
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} set of the driving signing parameters
     * @return {@link ToBeSigned}
     */
    ToBeSigned getDataToSignForKeyBindingSignature(DSSDocument signedAttestation, List<D> disclosures, E keyBindingParameters, SP signatureParameters);

    /**
     * Produces a key-binding signature document from the supplied signature value.
     * <p>
     * The signature value must sign the DTBS previously
     * obtained through {@link #getDataToSignForKeyBindingSignature(DSSDocument, KeyBindingParameters, SerializableSignatureParameters)}.
     *
     * @param signedAttestation
     *            {@link DSSDocument} signed attestation
     * @param keyBindingParameters
     *            {@link KeyBindingParameters} key-binding configuration
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} signature configuration
     * @param signatureValue
     *            {@link SignatureValue}
     * @return {@link DSSDocument} key-binding signature
     */
    DSSDocument createKeyBindingSignature(DSSDocument signedAttestation, E keyBindingParameters, SP signatureParameters, SignatureValue signatureValue);

    /**
     * Produces a key-binding signature document from the supplied signature value and disclosures.
     * <p>
     * The signature value must sign the DTBS previously
     * obtained through {@link #getDataToSignForKeyBindingSignature(DSSDocument, List, KeyBindingParameters, SerializableSignatureParameters)}.
     *
     * @param signedAttestation
     *            {@link DSSDocument} representing a signed attestation
     * @param disclosures
     *            a list of {@link SelectiveDisclosure}s to be provided with the signedAttestation presentation
     * @param keyBindingParameters
     *            {@link KeyBindingParameters} key binding signature configuration
     * @param signatureParameters
     *            {@link SerializableSignatureParameters} set of the driving signing parameters
     * @param signatureValue
     *            {@link SignatureValue}
     * @return {@link DSSDocument} key-binding signature
     */
    DSSDocument createKeyBindingSignature(DSSDocument signedAttestation, List<D> disclosures, E keyBindingParameters, SP signatureParameters, SignatureValue signatureValue);

    /**
     * Creates an attestation presentation containing the signed attestation and
     * the supplied disclosures.
     *
     * @param signedAttestation
     *            {@link DSSDocument} signed attestation
     * @param disclosures
     *            a list of {@link SelectiveDisclosure}s to be included in the presentation
     * @return {@link DSSDocument} Attestation Presentation
     */
    DSSDocument issuePresentation(DSSDocument signedAttestation, List<D> disclosures);

    /**
     * Creates an attestation presentation containing the signed attestation and a
     * holder key-binding signature.
     *
     * @param signedAttestation
     *            {@link DSSDocument} signed attestation
     * @param keyBinding
     *            {@link DSSDocument} key binding signature
     * @return {@link DSSDocument} Attestation Presentation
     */
    DSSDocument issuePresentation(DSSDocument signedAttestation, DSSDocument keyBinding);

    /**
     * Creates an attestation presentation containing the signed attestation, the
     * selected disclosures, and a holder key-binding signature.
     *
     * @param signedAttestation
     *            {@link DSSDocument} signed attestation
     * @param disclosures
     *            a list of {@link SelectiveDisclosure}s to be included in the presentation
     * @param keyBinding
     *            {@link DSSDocument} key binding signature
     * @return {@link DSSDocument} Attestation Presentation
     */
    DSSDocument issuePresentation(DSSDocument signedAttestation, List<D> disclosures, DSSDocument keyBinding);

}
