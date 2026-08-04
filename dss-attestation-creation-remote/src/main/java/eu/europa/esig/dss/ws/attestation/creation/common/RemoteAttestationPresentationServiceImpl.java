package eu.europa.esig.dss.ws.attestation.creation.common;

import eu.europa.esig.dss.attestation.common.creation.AttestationDocument;
import eu.europa.esig.dss.attestation.common.creation.AttestationPresentationService;
import eu.europa.esig.dss.attestation.common.creation.AttestationService;
import eu.europa.esig.dss.attestation.common.creation.KeyBindingParameters;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocDeviceSignedParameters;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocIssuerSignedItem;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocService;
import eu.europa.esig.dss.enumerations.AttestationForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.ws.attestation.creation.common.builder.RemoteAttestationCreationSignatureParametersBuilder;
import eu.europa.esig.dss.ws.attestation.creation.common.builder.RemoteAttestationPresentationParametersBuilder;
import eu.europa.esig.dss.ws.attestation.creation.common.builder.RemoteKeyBindingParametersBuilder;
import eu.europa.esig.dss.ws.attestation.creation.common.converter.DisclosureFromDTOConverter;
import eu.europa.esig.dss.ws.attestation.creation.common.converter.RemoteAttestationConverter;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationParsingParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPresentationParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteKeyBindingParameters;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Default implementation of the {@code eu.europa.esig.dss.ws.attestation.creation.common.RemoteAttestationPresentationService}
 *
 */
public class RemoteAttestationPresentationServiceImpl extends AbstractRemoteAttestationCreationService implements RemoteAttestationPresentationService {

    private static final long serialVersionUID = 1052179152244214939L;

    private static final Logger LOG = LoggerFactory.getLogger(RemoteAttestationPresentationServiceImpl.class);

    /**
     * Default constructor
     */
    public RemoteAttestationPresentationServiceImpl() {
        // empty
    }

    @SuppressWarnings({"rawtypes"})
    @Override
    public RemoteAttestationDocument parseAttestation(RemoteDocument attestation, RemoteAttestationParsingParameters attestationParsingParameters) {
        Objects.requireNonNull(attestation, "Attestation must be defined!");
        Objects.requireNonNull(attestationParsingParameters, "attestationParsingParameters must be defined!");
        Objects.requireNonNull(attestationParsingParameters.getAttestationForm(), "attestationForm must be defined!");
        LOG.info("ParseAttestation in process...");

        AttestationPresentationService attestationService = getAttestationPresentationServiceForType(attestationParsingParameters.getAttestationForm());

        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(attestation);
        AttestationDocument parsedAttestation = attestationService.parseAttestation(dssDocument);

        LOG.info("ParseAttestation is finished");
        return RemoteAttestationConverter.toRemoteAttestationDocument(parsedAttestation);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public ToBeSignedDTO getDataToSignForKeyBindingSignature(RemoteDocument attestation, List<DisclosureDTO> disclosureDTOs,
                                                             RemoteKeyBindingParameters keyBindingParametersDTO, RemoteSignatureParameters signatureParameters) throws DSSException {
        Objects.requireNonNull(attestation, "Attestation must be defined!");
        Objects.requireNonNull(keyBindingParametersDTO, "keyBindingParameters must be defined!");
        Objects.requireNonNull(keyBindingParametersDTO.getAttestationForm(), "attestationForm must be defined!");
        Objects.requireNonNull(signatureParameters, "signatureParameters must be defined!");
        LOG.info("GetDataToSignForKeyBindingSignature in process...");

        KeyBindingParameters keyBindingParameters = new RemoteKeyBindingParametersBuilder(keyBindingParametersDTO).build();
        SerializableSignatureParameters parameters = new RemoteAttestationCreationSignatureParametersBuilder(keyBindingParametersDTO.getAttestationForm(), signatureParameters).build();
        AttestationPresentationService attestationService = getAttestationPresentationServiceForType(keyBindingParametersDTO.getAttestationForm());

        List<SelectiveDisclosure> disclosures = toAttestationDisclosures(keyBindingParametersDTO.getAttestationForm(), disclosureDTOs);

        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(attestation);

        ToBeSigned toBeSigned = attestationService.getDataToSignForKeyBindingSignature(dssDocument, disclosures, keyBindingParameters, parameters);
        LOG.info("GetDataToSignForKeyBindingSignature is finished");
        return DTOConverter.toToBeSignedDTO(toBeSigned);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public RemoteDocument createKeyBindingSignature(RemoteDocument attestation, List<DisclosureDTO> disclosureDTOs, RemoteKeyBindingParameters keyBindingParametersDTO,
                                                    RemoteSignatureParameters signatureParameters, SignatureValueDTO signatureValueDTO) throws DSSException {
        Objects.requireNonNull(attestation, "Attestation must be defined!");
        Objects.requireNonNull(keyBindingParametersDTO, "keyBindingParameters must be defined!");
        Objects.requireNonNull(keyBindingParametersDTO.getAttestationForm(), "attestationForm must be defined!");
        Objects.requireNonNull(signatureParameters, "signatureParameters must be defined!");
        Objects.requireNonNull(signatureValueDTO, "signatureValue must be defined!");
        LOG.info("CreateKeyBindingSignature in process...");

        KeyBindingParameters keyBindingParameters = new RemoteKeyBindingParametersBuilder(keyBindingParametersDTO).build();
        SerializableSignatureParameters parameters = new RemoteAttestationCreationSignatureParametersBuilder(keyBindingParametersDTO.getAttestationForm(), signatureParameters).build();
        AttestationPresentationService attestationService = getAttestationPresentationServiceForType(keyBindingParametersDTO.getAttestationForm());

        List<SelectiveDisclosure> disclosures = toAttestationDisclosures(keyBindingParametersDTO.getAttestationForm(), disclosureDTOs);

        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(attestation);

        DSSDocument keyBindingSignature = attestationService.createKeyBindingSignature(
                dssDocument, disclosures, keyBindingParameters, parameters, toSignatureValue(signatureValueDTO));
        LOG.info("CreateKeyBindingSignature is finished");
        return RemoteDocumentConverter.toRemoteDocument(keyBindingSignature);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public RemoteDocument issuePresentation(RemoteDocument attestation, List<DisclosureDTO> disclosureDTOs,
                                            RemoteDocument keyBinding, RemoteAttestationPresentationParameters presentationParameters) throws DSSException {
        Objects.requireNonNull(attestation, "Attestation must be defined!");
        Objects.requireNonNull(presentationParameters, "presentationParameters must be defined!");
        Objects.requireNonNull(presentationParameters.getAttestationForm(), "attestationForm must be defined!");
        LOG.info("IssuePresentation in process...");

        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(attestation);
        DSSDocument keyBindingDocument = RemoteDocumentConverter.toDSSDocument(keyBinding);
        List<SelectiveDisclosure> disclosures = toAttestationDisclosures(presentationParameters.getAttestationForm(), disclosureDTOs);
        AttestationPresentationService attestationService = getAttestationPresentationServiceForType(presentationParameters.getAttestationForm());
        DSSDocument attestationPresentation;
        switch (presentationParameters.getAttestationForm()) {
            case SD_JWT:
                attestationPresentation = attestationService.issuePresentation(dssDocument, disclosures, keyBindingDocument);
                break;
            case MDOC:
                List<MdocIssuerSignedItem> mdocAttestationDisclosures = disclosures.stream().map(d -> (MdocIssuerSignedItem) d).collect(Collectors.toList());
                MdocDeviceSignedParameters deviceSignedParameters = new RemoteAttestationPresentationParametersBuilder(
                        presentationParameters).buildMdocDeviceSignedParameters();
                attestationPresentation = ((MdocService) attestationService).issuePresentation(
                        dssDocument, mdocAttestationDisclosures, keyBindingDocument, deviceSignedParameters);
                break;
            default:
                throw new UnsupportedOperationException(String.format(
                        "Unsupported attestation format: '%s'. SD-JWT and ISO/IEC mdoc are only supported.", presentationParameters.getAttestationForm()));
        }
        LOG.info("IssuePresentation is finished");
        return RemoteDocumentConverter.toRemoteDocument(attestationPresentation);
    }

    @SuppressWarnings({"rawtypes"})
    protected AttestationPresentationService getAttestationPresentationServiceForType(AttestationForm attestationForm) {
        AttestationService service = super.getAttestationServiceForType(attestationForm);
        if (service instanceof AttestationPresentationService) {
            return (AttestationPresentationService) service;
        }
        throw new IllegalStateException("The service '%s' does not implement AttestationPresentationService! " +
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
