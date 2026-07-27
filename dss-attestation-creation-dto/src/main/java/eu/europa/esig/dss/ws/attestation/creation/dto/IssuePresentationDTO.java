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
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPresentationParameters;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * This class is a DTO to transfer required objects to execute issuePresentation method
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation)
 */
public class IssuePresentationDTO implements Serializable {

    private static final long serialVersionUID = -9072162299836706092L;

    /** Signed attestation document */
    private RemoteDocument attestation;

    /** (Optional) List of disclosures */
    private List<DisclosureDTO> disclosures;

    /** (Optional) Key binding signature document */
    private RemoteDocument keyBindingSignature;

    /** Parameters for the attestation presentation */
    private RemoteAttestationPresentationParameters presentationParameters;

    /**
     * Empty constructor
     */
    public IssuePresentationDTO() {
        super();
    }

    /**
     * Default constructor
     *
     * @param attestation {@link RemoteDocument} attestation document
     * @param disclosures a list of {@link DisclosureDTO}s
     * @param keyBindingSignature {@link RemoteDocument} key binding signature document
     * @param presentationParameters {@link RemoteAttestationPresentationParameters}
     */
    public IssuePresentationDTO(RemoteDocument attestation, List<DisclosureDTO> disclosures, RemoteDocument keyBindingSignature,
                                RemoteAttestationPresentationParameters presentationParameters) {
        this.attestation = attestation;
        this.disclosures = disclosures;
        this.keyBindingSignature = keyBindingSignature;
        this.presentationParameters = presentationParameters;
    }

    /**
     * Gets the signed attestation document
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getAttestation() {
        return attestation;
    }

    /**
     * Sets a signed attestation document
     *
     * @param attestation {@link RemoteDocument}
     */
    public void setAttestation(RemoteDocument attestation) {
        this.attestation = attestation;
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
     * Gets the key binding signature document
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getKeyBindingSignature() {
        return keyBindingSignature;
    }

    /**
     * (Optional) Sets the key binding signature document
     *
     * @param keyBindingSignature {@link RemoteDocument}
     */
    public void setKeyBindingSignature(RemoteDocument keyBindingSignature) {
        this.keyBindingSignature = keyBindingSignature;
    }

    /**
     * Gets the Attestation Presentation parameters
     *
     * @return {@link RemoteAttestationPresentationParameters}
     */
    public RemoteAttestationPresentationParameters getPresentationParameters() {
        return presentationParameters;
    }

    /**
     * Sets the Attestation Presentation parameters
     *
     * @param presentationParameters {@link RemoteAttestationPresentationParameters}
     */
    public void setPresentationParameters(RemoteAttestationPresentationParameters presentationParameters) {
        this.presentationParameters = presentationParameters;
    }

    @Override
    public String toString() {
        return "IssuePresentationDTO [" +
                "attestation=" + attestation +
                ", disclosures=" + disclosures +
                ", keyBindingSignature=" + keyBindingSignature +
                ", presentationParameters=" + presentationParameters +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        IssuePresentationDTO that = (IssuePresentationDTO) object;
        return Objects.equals(attestation, that.attestation)
                && Objects.equals(disclosures, that.disclosures)
                && Objects.equals(keyBindingSignature, that.keyBindingSignature)
                && Objects.equals(presentationParameters, that.presentationParameters);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(attestation);
        result = 31 * result + Objects.hashCode(disclosures);
        result = 31 * result + Objects.hashCode(keyBindingSignature);
        result = 31 * result + Objects.hashCode(presentationParameters);
        return result;
    }

}
