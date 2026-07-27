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
package eu.europa.esig.dss.attestation.common.validation;

import eu.europa.esig.dss.enumerations.AttestationDocumentFormat;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.attestation.AttestationPresentation;

import java.util.List;

/**
 * Abstract implementation of an Attestation Presentation
 */
public abstract class DefaultAttestationPresentation implements AttestationPresentation {

    /** Type of the Attestation Presentation */
    private AttestationDocumentFormat attestationDocumentFormat;

    /** List of incorporated Electronic Attestations of Attributes */
    private List<Attestation> electronicAttestationsOfAttributes;

    /**
     * Default constructor
     */
    protected DefaultAttestationPresentation() {
        // empty
    }

    @Override
    public AttestationDocumentFormat getDocumentFormat() {
        return attestationDocumentFormat;
    }

    /**
     * Sets the type of the Attestation Presentation document
     *
     * @param attestationDocumentFormat {@link AttestationDocumentFormat}
     */
    public void setAttestationPresentationType(AttestationDocumentFormat attestationDocumentFormat) {
        this.attestationDocumentFormat = attestationDocumentFormat;
    }

    @Override
    public List<Attestation> getAttestations() {
        return electronicAttestationsOfAttributes;
    }

    /**
     * Sets a list of incorporated Electronic Attestations of Attributes
     *
     * @param electronicAttestationsOfAttributes a list of {@link Attestation}
     */
    public void setElectronicAttestationsOfAttributes(List<Attestation> electronicAttestationsOfAttributes) {
        this.electronicAttestationsOfAttributes = electronicAttestationsOfAttributes;
    }

}
