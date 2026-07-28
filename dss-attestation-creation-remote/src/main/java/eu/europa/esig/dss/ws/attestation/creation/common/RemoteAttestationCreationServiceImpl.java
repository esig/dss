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
package eu.europa.esig.dss.ws.attestation.creation.common;

import eu.europa.esig.dss.attestation.common.creation.AttestationPayloadParameters;
import eu.europa.esig.dss.attestation.common.creation.AttestationService;
import eu.europa.esig.dss.attestation.common.creation.KeyBindingParameters;
import eu.europa.esig.dss.attestation.common.creation.SelectiveDisclosure;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocDeviceSignedParameters;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocSelectiveDisclosure;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocService;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTService;
import eu.europa.esig.dss.enumerations.AttestationForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.ws.attestation.creation.common.builder.RemoteAttestationCreationSignatureParametersBuilder;
import eu.europa.esig.dss.ws.attestation.creation.common.builder.RemoteAttestationPayloadParametersBuilder;
import eu.europa.esig.dss.ws.attestation.creation.common.builder.RemoteAttestationPresentationParametersBuilder;
import eu.europa.esig.dss.ws.attestation.creation.common.builder.RemoteKeyBindingParametersBuilder;
import eu.europa.esig.dss.ws.attestation.creation.common.converter.DisclosureFromDTOConverter;
import eu.europa.esig.dss.ws.attestation.creation.common.converter.DisclosureToDTOConverter;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
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
 * Default implementation of the {@code eu.europa.esig.dss.ws.attestation.creation.common.RemoteAttestationCreationService}
 *
 */
public class RemoteAttestationCreationServiceImpl implements RemoteAttestationCreationService {

    private static final long serialVersionUID = -8392274758014040836L;

    private static final Logger LOG = LoggerFactory.getLogger(RemoteAttestationCreationServiceImpl.class);

    /**
     * SD-JWT service
     */
    private SDJWTService sdjwtService;

    /**
     * Mdoc attestation service
     */
    private MdocService mdocService;

    /**
     * Default constructor
     */
    public RemoteAttestationCreationServiceImpl() {
        // empty
    }

    /**
     * Sets the SD-JWT attestation service
     *
     * @param sdjwtService {@link SDJWTService}
     */
    public void setSdjwtService(SDJWTService sdjwtService) {
        this.sdjwtService = sdjwtService;
    }

    /**
     * Sets the mdoc service
     *
     * @param mdocService {@link MdocService}
     */
    public void setMdocService(MdocService mdocService) {
        this.mdocService = mdocService;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public ToBeSignedDTO getDataToSign(RemoteAttestationPayloadParameters payloadParameters, RemoteSignatureParameters signatureParameters) throws DSSException {
        Objects.requireNonNull(payloadParameters, "payloadParameters must be defined!");
        Objects.requireNonNull(payloadParameters.getAttestationForm(), "attestationProfile must be defined!");
        Objects.requireNonNull(signatureParameters, "signatureParameters must be defined!");
        LOG.info("GetDataToSign for attestation signature in process...");

        SerializableSignatureParameters parameters = new RemoteAttestationCreationSignatureParametersBuilder(payloadParameters.getAttestationForm(), signatureParameters).build();
        AttestationService attestationService = getAttestationServiceForType(payloadParameters.getAttestationForm());

        ToBeSigned toBeSigned;
        if (payloadParameters.getPreComputedPayload() != null) {
            DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(payloadParameters.getPreComputedPayload());
            toBeSigned = attestationService.getDataToBeSigned(dssDocument, parameters);
        } else {
            AttestationPayloadParameters attestationPayloadParameters = new RemoteAttestationPayloadParametersBuilder(payloadParameters).build();
            toBeSigned = attestationService.getDataToBeSigned(attestationPayloadParameters, parameters);
        }
        LOG.info("GetDataToSign for attestation signature is finished");
        return DTOConverter.toToBeSignedDTO(toBeSigned);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public RemoteDocument signAttestation(RemoteAttestationPayloadParameters payloadParameters, RemoteSignatureParameters signatureParameters,
                                  SignatureValueDTO signatureValueDTO) throws DSSException {
        Objects.requireNonNull(payloadParameters, "payloadParameters must be defined!");
        Objects.requireNonNull(payloadParameters.getAttestationForm(), "attestationProfile must be defined!");
        Objects.requireNonNull(signatureParameters, "signatureParameters must be defined!");
        Objects.requireNonNull(signatureValueDTO, "signatureValue must be defined!");
        LOG.info("SignAttestation in process...");

        SerializableSignatureParameters parameters = new RemoteAttestationCreationSignatureParametersBuilder(payloadParameters.getAttestationForm(), signatureParameters).build();
        AttestationService attestationService = getAttestationServiceForType(payloadParameters.getAttestationForm());

        DSSDocument signedAttestation;
        if (payloadParameters.getPreComputedPayload() != null) {
            DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(payloadParameters.getPreComputedPayload());
            signedAttestation = attestationService.signAttestation(dssDocument, parameters, toSignatureValue(signatureValueDTO));
        } else {
            AttestationPayloadParameters attestationPayloadParameters = new RemoteAttestationPayloadParametersBuilder(payloadParameters).build();
            signedAttestation = attestationService.signAttestation(attestationPayloadParameters, parameters, toSignatureValue(signatureValueDTO));
        }
        LOG.info("SignAttestation is finished");
        return RemoteDocumentConverter.toRemoteDocument(signedAttestation);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public List<DisclosureDTO> getDisclosures(RemoteAttestationPayloadParameters payloadParameters) throws DSSException {
        Objects.requireNonNull(payloadParameters, "payloadParameters must be defined!");
        Objects.requireNonNull(payloadParameters.getAttestationForm(), "attestationProfile must be defined!");
        LOG.info("GetDisclosures in process...");

        AttestationService attestationService = getAttestationServiceForType(payloadParameters.getAttestationForm());
        AttestationPayloadParameters attestationPayloadParameters = new RemoteAttestationPayloadParametersBuilder(payloadParameters).build();

        List<? extends SelectiveDisclosure> disclosures = attestationService.getDisclosures(attestationPayloadParameters);
        List<DisclosureDTO> disclosureDTOs = disclosures.stream().map(new DisclosureToDTOConverter()).collect(Collectors.toList());

        LOG.info("GetDisclosures is finished");
        return disclosureDTOs;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public ToBeSignedDTO getDataToSignForKeyBindingSignature(RemoteDocument attestation, List<DisclosureDTO> disclosureDTOs,
                                                             RemoteKeyBindingParameters keyBindingParametersDTO, RemoteSignatureParameters signatureParameters) throws DSSException {
        Objects.requireNonNull(attestation, "Attestation must be defined!");
        Objects.requireNonNull(keyBindingParametersDTO, "keyBindingParameters must be defined!");
        Objects.requireNonNull(keyBindingParametersDTO.getAttestationForm(), "attestationProfile must be defined!");
        Objects.requireNonNull(signatureParameters, "signatureParameters must be defined!");
        LOG.info("GetDataToSignForKeyBindingSignature in process...");

        KeyBindingParameters keyBindingParameters = new RemoteKeyBindingParametersBuilder(keyBindingParametersDTO).build();
        SerializableSignatureParameters parameters = new RemoteAttestationCreationSignatureParametersBuilder(keyBindingParametersDTO.getAttestationForm(), signatureParameters).build();
        AttestationService attestationService = getAttestationServiceForType(keyBindingParametersDTO.getAttestationForm());

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
        Objects.requireNonNull(keyBindingParametersDTO.getAttestationForm(), "attestationProfile must be defined!");
        Objects.requireNonNull(signatureParameters, "signatureParameters must be defined!");
        Objects.requireNonNull(signatureValueDTO, "signatureValue must be defined!");
        LOG.info("CreateKeyBindingSignature in process...");

        KeyBindingParameters keyBindingParameters = new RemoteKeyBindingParametersBuilder(keyBindingParametersDTO).build();
        SerializableSignatureParameters parameters = new RemoteAttestationCreationSignatureParametersBuilder(keyBindingParametersDTO.getAttestationForm(), signatureParameters).build();
        AttestationService attestationService = getAttestationServiceForType(keyBindingParametersDTO.getAttestationForm());

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
        Objects.requireNonNull(presentationParameters.getAttestationForm(), "attestationProfile must be defined!");
        LOG.info("IssuePresentation in process...");

        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(attestation);
        DSSDocument keyBindingDocument = RemoteDocumentConverter.toDSSDocument(keyBinding);
        List<SelectiveDisclosure> disclosures = toAttestationDisclosures(presentationParameters.getAttestationForm(), disclosureDTOs);
        AttestationService attestationService = getAttestationServiceForType(presentationParameters.getAttestationForm());
        DSSDocument attestationPresentation;
        switch (presentationParameters.getAttestationForm()) {
            case SD_JWT:
                attestationPresentation = attestationService.issuePresentation(dssDocument, disclosures, keyBindingDocument);
                break;
            case MDOC:
                List<MdocSelectiveDisclosure> mdocAttestationDisclosures = disclosures.stream().map(d -> (MdocSelectiveDisclosure) d).collect(Collectors.toList());
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

    /**
     * Transforms {@code SignatureValueDTO} to {@code SignatureValue}
     *
     * @param signatureValueDTO {@link SignatureValueDTO}
     * @return {@link SignatureValue}
     */
    protected SignatureValue toSignatureValue(SignatureValueDTO signatureValueDTO) {
        return new SignatureValue(signatureValueDTO.getAlgorithm(), signatureValueDTO.getValue());
    }

    private List<SelectiveDisclosure> toAttestationDisclosures(AttestationForm attestationForm, List<DisclosureDTO> disclosureDTOs) {
        if (disclosureDTOs != null && !disclosureDTOs.isEmpty()) {
            return disclosureDTOs.stream().map(
                    new DisclosureFromDTOConverter(attestationForm)).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    @SuppressWarnings("rawtypes")
    private AttestationService getAttestationServiceForType(AttestationForm attestationForm) {
        AttestationService attestationService;
        switch (attestationForm) {
            case SD_JWT:
                attestationService = sdjwtService;
                break;
            case MDOC:
                attestationService = mdocService;
                break;
            default:
                throw new UnsupportedOperationException(String.format(
                        "Unsupported attestation format: '%s'. SD-JWT and ISO/IEC mdoc are only supported.", attestationForm));
        }
        if (attestationService == null) {
            throw new NullPointerException(String.format("No service has been provided for the attestation form '%s'", attestationForm));
        }
        return attestationService;
    }

}
