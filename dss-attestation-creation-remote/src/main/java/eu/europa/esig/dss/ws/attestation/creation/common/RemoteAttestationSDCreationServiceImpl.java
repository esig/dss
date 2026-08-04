package eu.europa.esig.dss.ws.attestation.creation.common;

import eu.europa.esig.dss.attestation.common.creation.AttestationPayloadParameters;
import eu.europa.esig.dss.attestation.common.creation.AttestationSDService;
import eu.europa.esig.dss.attestation.common.creation.AttestationService;
import eu.europa.esig.dss.enumerations.AttestationForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.ws.attestation.creation.common.builder.RemoteAttestationPayloadParametersBuilder;
import eu.europa.esig.dss.ws.attestation.creation.common.converter.DisclosureFromDTOConverter;
import eu.europa.esig.dss.ws.attestation.creation.common.converter.DisclosureToDTOConverter;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Default implementation of the {@code eu.europa.esig.dss.ws.attestation.creation.common.RemoteAttestationSDCreationService}
 *
 */
public class RemoteAttestationSDCreationServiceImpl extends RemoteAttestationCreationServiceImpl implements RemoteAttestationSDCreationService {

    private static final long serialVersionUID = 5224894875264340170L;

    private static final Logger LOG = LoggerFactory.getLogger(RemoteAttestationSDCreationServiceImpl.class);

    /**
     * Default constructor
     */
    public RemoteAttestationSDCreationServiceImpl() {
        // empty
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public List<DisclosureDTO> generateDisclosures(RemoteAttestationPayloadParameters payloadParameters) {
        Objects.requireNonNull(payloadParameters, "payloadParameters must be defined!");
        Objects.requireNonNull(payloadParameters.getAttestationForm(), "attestationForm must be defined!");
        LOG.info("GenerateDisclosures in process...");

        AttestationSDService attestationService = getAttestationServiceForType(payloadParameters.getAttestationForm());
        AttestationPayloadParameters attestationPayloadParameters = new RemoteAttestationPayloadParametersBuilder(payloadParameters).build();

        List<? extends SelectiveDisclosure> disclosures = attestationService.generateDisclosures(attestationPayloadParameters);
        List<DisclosureDTO> disclosureDTOs = disclosures.stream().map(new DisclosureToDTOConverter()).collect(Collectors.toList());

        LOG.info("GenerateDisclosures is finished");
        return disclosureDTOs;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public RemoteDocument issueAttestation(RemoteDocument signedAttestation, RemoteAttestationPayloadParameters payloadParameters, List<DisclosureDTO> disclosures) {
        Objects.requireNonNull(signedAttestation, "signedAttestation must be defined!");
        Objects.requireNonNull(payloadParameters, "payloadParameters must be defined!");
        Objects.requireNonNull(payloadParameters.getAttestationForm(), "attestationForm must be defined!");
        LOG.info("IssueAttestation in process...");

        AttestationSDService attestationService = getAttestationServiceForType(payloadParameters.getAttestationForm());
        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(signedAttestation);
        AttestationPayloadParameters attestationPayloadParameters = new RemoteAttestationPayloadParametersBuilder(payloadParameters).build();

        DSSDocument attestationDocument;
        if (disclosures == null) {
            attestationDocument = attestationService.issueAttestation(dssDocument, attestationPayloadParameters);
        } else {
            List<SelectiveDisclosure> attestationDisclosures = toAttestationDisclosures(payloadParameters.getAttestationForm(), disclosures);
            attestationDocument = attestationService.issueAttestation(dssDocument, attestationDisclosures);
        }
        LOG.info("IssueAttestation is finished");
        return RemoteDocumentConverter.toRemoteDocument(attestationDocument);
    }

    @SuppressWarnings({"rawtypes"})
    @Override
    protected AttestationSDService getAttestationServiceForType(AttestationForm attestationForm) {
        AttestationService service = super.getAttestationServiceForType(attestationForm);
        if (service instanceof AttestationSDService) {
            return (AttestationSDService) service;
        }
        throw new IllegalStateException("The service '%s' does not implement AttestationSDService! " +
                "The requested function is not supported!");
    }

    private List<SelectiveDisclosure> toAttestationDisclosures(AttestationForm attestationForm, List<DisclosureDTO> disclosureDTOs) {
        if (disclosureDTOs != null && !disclosureDTOs.isEmpty()) {
            return disclosureDTOs.stream().map(
                    new DisclosureFromDTOConverter(attestationForm)).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

}
