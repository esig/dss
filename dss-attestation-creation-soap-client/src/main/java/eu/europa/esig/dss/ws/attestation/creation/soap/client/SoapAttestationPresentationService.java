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
package eu.europa.esig.dss.ws.attestation.creation.soap.client;

import eu.europa.esig.dss.ws.attestation.creation.dto.CreateKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignForKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssuePresentationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.ParseAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;

/**
 * This SOAP interface provides operations for the issuance of attestation presentation.
 *
 */
@WebService(targetNamespace = "http://attestation.presentation.dss.esig.europa.eu/")
public interface SoapAttestationPresentationService {

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
    @WebResult(name = "response")
    RemoteAttestationDocument parseAttestation(@WebParam(name = "parseAttestationDTO") final ParseAttestationDTO parseAttestationDTO);

    /**
     * Created a DataToBeSigned (DTBS) for a key-binding signature creation, format specific.
     *
     * @param dataToSignForKeyBindingSignatureDTO {@link DataToSignForKeyBindingSignatureDTO} a DTO with the needed
     *                        information (signed attestation, disclosures, key binding and signature parameter) to compute
     *                        the data to be signed for key binding signature
     * @return the data to be signed
     */
    @WebResult(name = "response")
    ToBeSignedDTO getDataToSignForKeyBindingSignature(@WebParam(name = "dataToSignForKeyBindingSignatureDTO") final DataToSignForKeyBindingSignatureDTO dataToSignForKeyBindingSignatureDTO);

    /**
     * Creates a key-binding signature, format specific.
     *
     * @param createKeyBindingSignatureDTO {@link CreateKeyBindingSignatureDTO} a DTO with the needed information
     *                        (signed attestation, disclosures, key binding and signature parameters and signature value)
     *                        to create the key binding signature
     * @return the key-binding signature document
     */
    @WebResult(name = "response")
    RemoteDocument createKeyBindingSignature(@WebParam(name = "createKeyBindingSignatureDTO") final CreateKeyBindingSignatureDTO createKeyBindingSignatureDTO);

    /**
     * Creates an Attestation Presentation, with provided selective disclosures and key binding signature
     *
     * @param issuePresentationDTO {@link IssuePresentationDTO} a DTO with the needed information
     *                        (signed attestation, disclosures, key binding signature and parameters)
     *                        to issue the Attestation Presentation
     * @return the Attestation Presentation
     */
    @WebResult(name = "response")
    RemoteDocument issuePresentation(@WebParam(name = "issuePresentationDTO") final IssuePresentationDTO issuePresentationDTO);

}
