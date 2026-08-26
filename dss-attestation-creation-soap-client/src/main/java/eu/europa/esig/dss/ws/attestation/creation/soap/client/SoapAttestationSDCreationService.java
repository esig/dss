package eu.europa.esig.dss.ws.attestation.creation.soap.client;

import eu.europa.esig.dss.ws.attestation.creation.dto.DisclosuresDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssueAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;

import java.util.List;

/**
 * This SOAP interface provides operations for the signing of an attestation with selective disclosures.
 *
 */
@WebService(targetNamespace = "http://attestation.sd.creation.dss.esig.europa.eu/")
public interface SoapAttestationSDCreationService extends SoapAttestationCreationService {

    /**
     * Gets a list of disclosures for all selectively disclosable claims defined within the parameters
     *
     * @param disclosuresDTO {@link DisclosuresDTO} a DTO with the needed
     *                       information (payload parameters) to
     *                       generate the attestation disclosures
     * @return a list of disclosures
     */
    @WebResult(name = "response")
    List<DisclosureDTO> generateDisclosures(@WebParam(name = "disclosuresDTO") final DisclosuresDTO disclosuresDTO);

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
    @WebResult(name = "response")
    RemoteDocument issueAttestation(@WebParam(name = "issueAttestationDTO") final IssueAttestationDTO issueAttestationDTO);

}
