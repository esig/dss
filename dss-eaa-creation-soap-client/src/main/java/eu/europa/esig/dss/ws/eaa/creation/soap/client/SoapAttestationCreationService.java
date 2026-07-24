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
package eu.europa.esig.dss.ws.eaa.creation.soap.client;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.CreateKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.DataToSignAttestationDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.DataToSignForKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.DisclosuresDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.IssuePresentationDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.SignAttestationDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.DisclosureDTO;
import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;

import java.io.Serializable;
import java.util.List;

/**
 * This SOAP interface provides operations for the signing of EAA and issuance of EAA presentations.
 *
 */
@WebService(targetNamespace = "http://eaa.creation.dss.esig.europa.eu/")
public interface SoapAttestationCreationService extends Serializable {

    /**
     * Retrieves the bytes of the data that need to be signed based on the {@code payload} and {@code parameters}.
     *
     * @param dataToSignAttestationDTO {@link DataToSignAttestationDTO} a DTO with the needed
     *                         information (payload and signature parameters) to compute the data
     *                         to be signed
     * @return the data to be signed
     */
    @WebResult(name = "response")
    ToBeSignedDTO getDataToSign(@WebParam(name = "dataToSignEAADTO") final DataToSignAttestationDTO dataToSignAttestationDTO);

    /**
     * Signs the EAA with the provided signatureValue.
     *
     * @param signAttestationDTO {@link SignAttestationDTO} a DTO with the needed
     *                   information (payload and signature parameters, signature value) to
     *                   generate the signed EAA
     * @return the signed document (signature signing the EAA)
     */
    @WebResult(name = "response")
    RemoteDocument signEAA(@WebParam(name = "signEAADTO") final SignAttestationDTO signAttestationDTO);

    /**
     * Gets a list of disclosures for all selectively disclosable claims defined within the parameters
     *
     * @param disclosuresDTO {@link DisclosuresDTO} a DTO with the needed
     *                       information (payload parameters) to
     *                       generate the EAA disclosures
     * @return a list of disclosures
     */
    @WebResult(name = "response")
    List<DisclosureDTO> getDisclosures(@WebParam(name = "disclosuresDTO") final DisclosuresDTO disclosuresDTO);

    /**
     * Created a DataToBeSigned (DTBS) for a key-binding signature creation, format specific.
     *
     * @param dataToSignForKeyBindingSignatureDTO {@link DataToSignForKeyBindingSignatureDTO} a DTO with the needed
     *                        information (signed EAA, disclosures, key binding and signature parameter) to compute
     *                        the data to be signed for key binding signature
     * @return the data to be signed
     */
    @WebResult(name = "response")
    ToBeSignedDTO getDataToSignForKeyBindingSignature(@WebParam(name = "dataToSignForKeyBindingSignatureDTO") final DataToSignForKeyBindingSignatureDTO dataToSignForKeyBindingSignatureDTO);

    /**
     * Creates a key-binding signature, format specific.
     *
     * @param createKeyBindingSignatureDTO {@link CreateKeyBindingSignatureDTO} a DTO with the needed information
     *                        (signed EAA, disclosures, key binding and signature parameters and signature value)
     *                        to create the key binding signature
     * @return the key-binding signature document
     */
    @WebResult(name = "response")
    RemoteDocument createKeyBindingSignature(@WebParam(name = "createKeyBindingSignatureDTO") final CreateKeyBindingSignatureDTO createKeyBindingSignatureDTO);

    /**
     * Creates an Attestation Presentation, with provided selective disclosures and key binding signature
     *
     * @param issuePresentationDTO {@link IssuePresentationDTO} a DTO with the needed information
     *                        (signed EAA, disclosures, key binding signature and parameters)
     *                        to issue the Attestation Presentation
     * @return the Attestation Presentation
     */
    @WebResult(name = "response")
    RemoteDocument issuePresentation(@WebParam(name = "issuePresentationDTO") final IssuePresentationDTO issuePresentationDTO);

}
