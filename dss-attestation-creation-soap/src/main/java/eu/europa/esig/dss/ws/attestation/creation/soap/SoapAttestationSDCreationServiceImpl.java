package eu.europa.esig.dss.ws.attestation.creation.soap;

import eu.europa.esig.dss.ws.attestation.creation.common.RemoteAttestationSDCreationService;
import eu.europa.esig.dss.ws.attestation.creation.dto.DisclosuresDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssueAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.soap.client.SoapAttestationSDCreationService;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;

/**
 * SOAP implementation of the remote attestation with selective disclosures creation service
 *
 */
public class SoapAttestationSDCreationServiceImpl extends SoapAttestationCreationServiceImpl implements SoapAttestationSDCreationService {

    private static final long serialVersionUID = -5824362174327062129L;

    /**
     * Default constructor
     */
    public SoapAttestationSDCreationServiceImpl() {
        // empty
    }

    @Override
    protected RemoteAttestationSDCreationService getService() {
        return (RemoteAttestationSDCreationService) super.getService();
    }

    /**
     * Sets the remote attestation creation service
     *
     * @param service {@link RemoteAttestationSDCreationService}
     */
    public void setService(RemoteAttestationSDCreationService service) {
        super.setService(service);
    }

    @Override
    public List<DisclosureDTO> generateDisclosures(DisclosuresDTO disclosuresDTO) {
        return getService().generateDisclosures(disclosuresDTO.getPayloadParameters());
    }

    @Override
    public RemoteDocument issueAttestation(IssueAttestationDTO issueAttestationDTO) {
        return getService().issueAttestation(issueAttestationDTO.getSignedAttestation(),
                issueAttestationDTO.getPayloadParameters(), issueAttestationDTO.getDisclosures());
    }

}
