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
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.ws.attestation.creation.common.builder.RemoteAttestationCreationSignatureParametersBuilder;
import eu.europa.esig.dss.ws.attestation.creation.common.builder.RemoteAttestationPayloadParametersBuilder;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPayloadParameters;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Default implementation of the {@code eu.europa.esig.dss.ws.attestation.creation.common.RemoteAttestationCreationService}
 *
 */
public class RemoteAttestationCreationServiceImpl extends AbstractRemoteAttestationCreationService implements RemoteAttestationCreationService {

    private static final long serialVersionUID = -8392274758014040836L;

    private static final Logger LOG = LoggerFactory.getLogger(RemoteAttestationCreationServiceImpl.class);
    /**
     * Default constructor
     */
    public RemoteAttestationCreationServiceImpl() {
        // empty
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public ToBeSignedDTO getDataToSign(RemoteAttestationPayloadParameters payloadParameters, RemoteSignatureParameters signatureParameters) throws DSSException {
        Objects.requireNonNull(payloadParameters, "payloadParameters must be defined!");
        Objects.requireNonNull(payloadParameters.getAttestationForm(), "attestationForm must be defined!");
        Objects.requireNonNull(signatureParameters, "signatureParameters must be defined!");
        LOG.info("GetDataToSign for attestation signature in process...");

        SerializableSignatureParameters parameters = new RemoteAttestationCreationSignatureParametersBuilder(payloadParameters.getAttestationForm(), signatureParameters).build();
        AttestationService attestationService = getAttestationServiceForType(payloadParameters.getAttestationForm());

        ToBeSigned toBeSigned;
        if (payloadParameters.getPreComputedPayload() != null) {
            DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(payloadParameters.getPreComputedPayload());
            toBeSigned = attestationService.getDataToSign(dssDocument, parameters);
        } else {
            AttestationPayloadParameters attestationPayloadParameters = new RemoteAttestationPayloadParametersBuilder(payloadParameters).build();
            toBeSigned = attestationService.getDataToSign(attestationPayloadParameters, parameters);
        }
        LOG.info("GetDataToSign for attestation signature is finished");
        return DTOConverter.toToBeSignedDTO(toBeSigned);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public RemoteDocument signAttestation(RemoteAttestationPayloadParameters payloadParameters, RemoteSignatureParameters signatureParameters,
                                  SignatureValueDTO signatureValueDTO) throws DSSException {
        Objects.requireNonNull(payloadParameters, "payloadParameters must be defined!");
        Objects.requireNonNull(payloadParameters.getAttestationForm(), "attestationForm must be defined!");
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

}
