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
package eu.europa.esig.dss.ws.attestation.creation.rest.client;

import eu.europa.esig.dss.ws.attestation.creation.dto.CreateKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.DataToSignForKeyBindingSignatureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.IssuePresentationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.ParseAttestationDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationDocument;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/**
 * This REST interface provides operations for parsing of attestation and issuing of attestation presentation.
 *
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RestAttestationPresentationService {

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
    @POST
    @Path("parseAttestation")
    RemoteAttestationDocument parseAttestation(final ParseAttestationDTO parseAttestationDTO);

    /**
     * Created a DataToBeSigned (DTBS) for a key-binding signature creation, format specific.
     *
     * @param dataToSignForKeyBindingSignatureDTO {@link DataToSignForKeyBindingSignatureDTO} a DTO with the needed
     *                        information (signed attestation, disclosures, key binding and signature parameter) to compute
     *                        the data to be signed for key binding signature
     * @return the data to be signed
     */
    @POST
    @Path("getDataToSignForKeyBindingSignature")
    ToBeSignedDTO getDataToSignForKeyBindingSignature(final DataToSignForKeyBindingSignatureDTO dataToSignForKeyBindingSignatureDTO);

    /**
     * Creates a key-binding signature, format specific.
     *
     * @param createKeyBindingSignatureDTO {@link CreateKeyBindingSignatureDTO} a DTO with the needed information
     *                        (signed attestation, disclosures, key binding and signature parameters and signature value)
     *                        to create the key binding signature
     * @return the key-binding signature document
     */
    @POST
    @Path("createKeyBindingSignature")
    RemoteDocument createKeyBindingSignature(final CreateKeyBindingSignatureDTO createKeyBindingSignatureDTO);

    /**
     * Creates an Attestation Presentation, with provided selective disclosures and key binding signature
     *
     * @param issuePresentationDTO {@link IssuePresentationDTO} a DTO with the needed information
     *                        (signed attestation, disclosures, key binding signature and parameters)
     *                        to issue the Attestation Presentation
     * @return the Attestation Presentation
     */
    @POST
    @Path("issuePresentation")
    RemoteDocument issuePresentation(final IssuePresentationDTO issuePresentationDTO);

}
