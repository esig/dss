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
package eu.europa.esig.dss.eaa.common.validation;

import eu.europa.esig.dss.enumerations.AttestationPresentationType;
import eu.europa.esig.dss.spi.eaa.Attestation;
import eu.europa.esig.dss.spi.eaa.AttestationPresentation;

import java.util.List;

/**
 * Abstract implementation of an Attestation Presentation
 */
public abstract class DefaultAttestationPresentation implements AttestationPresentation {

    /** Type of the Attestation Presentation */
    private AttestationPresentationType attestationPresentationType;

    /** List of incorporated Electronic Attestations of Attributes */
    private List<Attestation> electronicAttestationsOfAttributes;

    /**
     * Default constructor
     */
    protected DefaultAttestationPresentation() {
        // empty
    }

    @Override
    public AttestationPresentationType getEAAPresentationType() {
        return attestationPresentationType;
    }

    /**
     * Sets the type of the Attestation Presentation document
     *
     * @param attestationPresentationType {@link AttestationPresentationType}
     */
    public void setEAAPresentationType(AttestationPresentationType attestationPresentationType) {
        this.attestationPresentationType = attestationPresentationType;
    }

    @Override
    public List<Attestation> getElectronicAttestationsOfAttributes() {
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
