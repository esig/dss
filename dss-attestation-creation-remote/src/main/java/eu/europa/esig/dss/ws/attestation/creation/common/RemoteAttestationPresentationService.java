package eu.europa.esig.dss.ws.attestation.creation.common;

import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationParsingParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPresentationParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.io.Serializable;
import java.util.List;

public interface RemoteAttestationPresentationService extends Serializable {
    
    /**
     * Parses an issued attestation into its logical components.
     * <p>
     * This method is typically invoked by a wallet instance after receiving an
     * attestation from an issuer. The returned object contains the signed
     * attestation together with all available disclosures, allowing the wallet to
     * choose which claims will be presented.
     *
     * @param attestation
     *             {@link RemoteDocument} issued attestation
     * @param attestationParsingParameters
     *             {@link RemoteAttestationParsingParameters} parsing parameters
     * @return {@link RemoteAttestationDocument}
     */
    RemoteAttestationDocument parseAttestation(final RemoteDocument attestation, final RemoteAttestationParsingParameters attestationParsingParameters);

    /**
     * Created a DataToBeSigned (DTBS) for a key-binding signature creation, format specific.
     *
     * @param attestation
     *            document representing a signed attestation
     * @param disclosures
     *            (optional) a list of disclosures to be provided with the attestation presentation
     * @param keyBindingParameters
     *            key binding signature configuration
     * @param signatureParameters
     *            set of the driving signing parameters
     * @return the data to be signed
     */
    ToBeSignedDTO getDataToSignForKeyBindingSignature(final RemoteDocument attestation, final List<DisclosureDTO> disclosures,
                                                      final eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteKeyBindingParameters keyBindingParameters, final RemoteSignatureParameters signatureParameters);

    /**
     * Creates a key-binding signature, format specific.
     *
     * @param attestation
     *            document representing a signed attestation
     * @param disclosures
     *            (optional) a list of disclosures to be provided with the attestation presentation
     * @param keyBindingParameters
     *            key binding signature configuration
     * @param signatureParameters
     *            set of the driving signing parameters
     * @param signatureValue
     *            the signature value to incorporate
     * @return the key-binding signature document
     */
    RemoteDocument createKeyBindingSignature(final RemoteDocument attestation, final List<DisclosureDTO> disclosures,
                                             final eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteKeyBindingParameters keyBindingParameters, final RemoteSignatureParameters signatureParameters,
                                             final SignatureValueDTO signatureValue);

    /**
     * Creates an Attestation Presentation, with provided selective disclosures and key binding signature
     *
     * @param attestation
     *            document representing a signed attestation
     * @param disclosures
     *            (optional) a list of disclosures to be provided with the attestation presentation
     * @param keyBinding
     *            (optional) document representing a key binding signature
     * @param presentationParameters
     *            configuration of the Attestation Presentation
     * @return the Attestation Presentation
     */
    RemoteDocument issuePresentation(final RemoteDocument attestation, final List<DisclosureDTO> disclosures,
                                     final RemoteDocument keyBinding, final RemoteAttestationPresentationParameters presentationParameters);
    
}
