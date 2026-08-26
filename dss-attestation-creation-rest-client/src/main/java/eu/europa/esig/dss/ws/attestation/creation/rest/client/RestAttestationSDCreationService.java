package eu.europa.esig.dss.ws.attestation.creation.rest.client;

import eu.europa.esig.dss.ws.attestation.creation.dto.DisclosuresDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssueAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import java.util.List;

/**
 * This REST interface provides operations for the signing of attestation with selective disclosures.
 *
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestAttestationSDCreationService extends RestAttestationCreationService {

    /**
     * Gets a list of disclosures for all selectively disclosable claims defined within the parameters
     *
     * @param disclosuresDTO {@link DisclosuresDTO} a DTO with the needed
     *                       information (payload parameters) to
     *                       generate the attestation disclosures
     * @return a list of disclosures
     */
    @POST
    @Path("generateDisclosures")
    List<DisclosureDTO> generateDisclosures(final DisclosuresDTO disclosuresDTO);

    /**
     * Creates an issued attestation and automatically attaches all disclosures
     * generated from the supplied payload parameters or uses the provided disclosures.
     * NOTE: when a list of disclosures is provided, the list will be used instead of payload parameters.
     * For an attestation without disclosures, please define an empty list of disclosures.
     *
     * @param issueAttestationDTO
     *             {@link IssueAttestationDTO}
     * @return {@link RemoteDocument} attestation document
     */
    @POST
    @Path("issueAttestation")
    RemoteDocument issueAttestation(final IssueAttestationDTO issueAttestationDTO);

}
