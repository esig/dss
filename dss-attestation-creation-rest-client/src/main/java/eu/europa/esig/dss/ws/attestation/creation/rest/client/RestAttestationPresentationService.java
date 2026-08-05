package eu.europa.esig.dss.ws.attestation.creation.rest.client;

import eu.europa.esig.dss.ws.attestation.creation.dto.CreateKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignForKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssuePresentationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.ParseAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/**
 * This REST interface provides operations for parsing of attestation and issuing of attestation presentation.
 *
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestAttestationPresentationService {

    /**
     * Parses an issued attestation into its logical components.
     * <p>
     * This method is typically invoked by a wallet instance after receiving an
     * attestation from an issuer. The returned object contains the signed
     * attestation together with all available disclosures, allowing the wallet to
     * choose which claims will be presented.
     *
     * @param parseAttestationDTO {@link ParseAttestationDTO} a DTO with the needed
     *                        information (attestation document and parameters) to parse the attestation
     * @return {@link RemoteAttestationDocument}
     */
    @POST
    @Path("parseAttestation")
    RemoteAttestationDocument parseAttestation(final ParseAttestationDTO parseAttestationDTO);

    /**
     * Created a DataToBeSigned (DTBS) for a key-binding signature creation, format specific.
     *
     * @param dataToSignForKeyBindingSignatureDTO {@link DataToSignForKeyBindingSignatureDTO} a DTO with the needed
     *                        information (signed attestation, disclosures, key binding and signature parameter) to compute
     *                        the data to be signed for key binding signature
     * @return the data to be signed
     */
    @POST
    @Path("getDataToSignForKeyBindingSignature")
    ToBeSignedDTO getDataToSignForKeyBindingSignature(final DataToSignForKeyBindingSignatureDTO dataToSignForKeyBindingSignatureDTO);

    /**
     * Creates a key-binding signature, format specific.
     *
     * @param createKeyBindingSignatureDTO {@link CreateKeyBindingSignatureDTO} a DTO with the needed information
     *                        (signed attestation, disclosures, key binding and signature parameters and signature value)
     *                        to create the key binding signature
     * @return the key-binding signature document
     */
    @POST
    @Path("createKeyBindingSignature")
    RemoteDocument createKeyBindingSignature(final CreateKeyBindingSignatureDTO createKeyBindingSignatureDTO);

    /**
     * Creates an Attestation Presentation, with provided selective disclosures and key binding signature
     *
     * @param issuePresentationDTO {@link IssuePresentationDTO} a DTO with the needed information
     *                        (signed attestation, disclosures, key binding signature and parameters)
     *                        to issue the Attestation Presentation
     * @return the Attestation Presentation
     */
    @POST
    @Path("issuePresentation")
    RemoteDocument issuePresentation(final IssuePresentationDTO issuePresentationDTO);

}
