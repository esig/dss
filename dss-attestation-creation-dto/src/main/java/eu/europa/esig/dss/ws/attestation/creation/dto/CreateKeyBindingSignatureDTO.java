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
package eu.europa.esig.dss.ws.attestation.creation.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteKeyBindingParameters;
import eu.europa.esig.dss.ws.signature.dto.AbstractSignDocumentDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.List;

/**
 * This class is a DTO to transfer required objects to execute createKeyBindingSignature method
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation)
 */
public class CreateKeyBindingSignatureDTO extends AbstractSignDocumentDTO {

    private static final long serialVersionUID = -6759188412043606519L;

    /** Signed attestation document */
    private RemoteDocument signedAttestation;

    /** (Optional) List of disclosures */
    private List<DisclosureDTO> disclosures;

    /** Parameters for key binding signature creation */
    private RemoteKeyBindingParameters keyBindingParameters;

    /**
     * Empty constructor
     */
    public CreateKeyBindingSignatureDTO() {
        super();
    }

    /**
     * Default constructor
     *
     * @param signedAttestation {@link RemoteDocument} attestation document
     * @param disclosures a list of {@link DisclosureDTO}s
     * @param keyBindingParameters {@link RemoteKeyBindingParameters}
     * @param signatureParameters {@link RemoteSignatureParameters}
     * @param signatureValueDTO {@link SignatureValueDTO}
     */
    public CreateKeyBindingSignatureDTO(RemoteDocument signedAttestation, List<DisclosureDTO> disclosures,
                                        RemoteKeyBindingParameters keyBindingParameters, RemoteSignatureParameters signatureParameters,
                                        SignatureValueDTO signatureValueDTO) {
        super(signatureParameters, signatureValueDTO);
        this.signedAttestation = signedAttestation;
        this.disclosures = disclosures;
        this.keyBindingParameters = keyBindingParameters;
    }

    /**
     * Gets the signed attestation document
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getSignedAttestation() {
        return signedAttestation;
    }

    /**
     * Sets a signed attestation document
     *
     * @param signedAttestation {@link RemoteDocument}
     */
    public void setSignedAttestation(RemoteDocument signedAttestation) {
        this.signedAttestation = signedAttestation;
    }

    /**
     * Gets a list of disclosures
     *
     * @return a list of {@link DisclosureDTO}s
     */
    public List<DisclosureDTO> getDisclosures() {
        return disclosures;
    }

    /**
     * (Optional) Sets a list of disclosures
     *
     * @param disclosures a list of {@link DisclosureDTO}s
     */
    public void setDisclosures(List<DisclosureDTO> disclosures) {
        this.disclosures = disclosures;
    }

    /**
     * Gets key binding signature parameters
     *
     * @return {@link RemoteKeyBindingParameters}
     */
    public RemoteKeyBindingParameters getKeyBindingParameters() {
        return keyBindingParameters;
    }

    /**
     * Sets key binding signature parameters
     *
     * @param keyBindingParameters {@link RemoteKeyBindingParameters}
     */
    public void setKeyBindingParameters(RemoteKeyBindingParameters keyBindingParameters) {
        this.keyBindingParameters = keyBindingParameters;
    }

}
