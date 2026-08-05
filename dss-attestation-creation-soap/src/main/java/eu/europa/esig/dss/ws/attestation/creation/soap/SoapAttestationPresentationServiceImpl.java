package eu.europa.esig.dss.ws.attestation.creation.soap;

import eu.europa.esig.dss.ws.attestation.creation.common.RemoteAttestationPresentationService;
import eu.europa.esig.dss.ws.attestation.creation.dto.CreateKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignForKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssuePresentationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.ParseAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument;
import eu.europa.esig.dss.ws.attestation.creation.soap.client.SoapAttestationPresentationService;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;

/**
 * Default implementation of the SOAP attestation presentation service
 *
 */
public class SoapAttestationPresentationServiceImpl implements SoapAttestationPresentationService {

    /** The service to use */
    private RemoteAttestationPresentationService service;

    /**
     * Default construction instantiating object with null SoapAttestationCreationService
     */
    public SoapAttestationPresentationServiceImpl() {
        // empty
    }

    /**
     * Gets the remote attestation presentation service
     *
     * @return {@link RemoteAttestationPresentationService}
     */
    protected RemoteAttestationPresentationService getService() {
        return service;
    }

    /**
     * Sets the remote attestation presentation service
     *
     * @param service {@link RemoteAttestationPresentationService}
     */
    public void setService(RemoteAttestationPresentationService service) {
        this.service = service;
    }

    @Override
    public RemoteAttestationDocument parseAttestation(ParseAttestationDTO parseAttestationDTO) {
        return getService().parseAttestation(parseAttestationDTO.getAttestation(), parseAttestationDTO.getAttestationParsingParameters());
    }

    @Override
    public ToBeSignedDTO getDataToSignForKeyBindingSignature(DataToSignForKeyBindingSignatureDTO dataToSignForKeyBindingSignatureDTO) {
        return getService().getDataToSignForKeyBindingSignature(dataToSignForKeyBindingSignatureDTO.getSignedAttestation(),
                dataToSignForKeyBindingSignatureDTO.getDisclosures(), dataToSignForKeyBindingSignatureDTO.getKeyBindingParameters(),
                dataToSignForKeyBindingSignatureDTO.getParameters());
    }

    @Override
    public RemoteDocument createKeyBindingSignature(CreateKeyBindingSignatureDTO createKeyBindingSignatureDTO) {
        return getService().createKeyBindingSignature(createKeyBindingSignatureDTO.getSignedAttestation(),
                createKeyBindingSignatureDTO.getDisclosures(), createKeyBindingSignatureDTO.getKeyBindingParameters(),
                createKeyBindingSignatureDTO.getParameters(), createKeyBindingSignatureDTO.getSignatureValue());
    }

    @Override
    public RemoteDocument issuePresentation(IssuePresentationDTO issuePresentationDTO) {
        return getService().issuePresentation(issuePresentationDTO.getAttestation(), issuePresentationDTO.getDisclosures(),
                issuePresentationDTO.getKeyBindingSignature(), issuePresentationDTO.getPresentationParameters());
    }

}
