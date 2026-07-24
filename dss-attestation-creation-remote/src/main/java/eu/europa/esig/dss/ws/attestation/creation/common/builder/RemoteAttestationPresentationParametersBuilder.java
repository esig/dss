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
package eu.europa.esig.dss.ws.attestation.creation.common.builder;

import eu.europa.esig.dss.attestation.mdoc.creation.MdocDeviceSignedParameters;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocKeyBindingParameters;
import eu.europa.esig.dss.ws.attestation.creation.common.converter.MdocClaimFromDTOConverter;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteAttestationPresentationParameters;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.RemoteKeyBindingParameters;

import java.util.Objects;

/**
 * Creates parameters for Attestation Presentation issuance
 *
 */
public class RemoteAttestationPresentationParametersBuilder {

    /** DTO representing the Attestation Presentation parameters */
    private final RemoteAttestationPresentationParameters remoteAttestationPresentationParameters;

    /**
     * Default constructor
     *
     * @param remoteAttestationPresentationParameters {@link RemoteKeyBindingParameters}
     */
    public RemoteAttestationPresentationParametersBuilder(final RemoteAttestationPresentationParameters remoteAttestationPresentationParameters) {
        Objects.requireNonNull(remoteAttestationPresentationParameters, "RemoteEAAPresentationParameters must be defined!");
        Objects.requireNonNull(remoteAttestationPresentationParameters.getEaaType(), "EAA type must be definedy!");
        this.remoteAttestationPresentationParameters = remoteAttestationPresentationParameters;
    }

    /**
     * Creates {@code MdocEAADeviceSignedParameters}
     *
     * @return {@link MdocDeviceSignedParameters}
     */
    public MdocDeviceSignedParameters buildMdocEAADeviceSignedParameters() {
        final MdocKeyBindingParameters mdocKeyBindingParameters = new MdocKeyBindingParameters();
        if (remoteAttestationPresentationParameters.getDeviceSignedDataElements() != null &&
                !remoteAttestationPresentationParameters.getDeviceSignedDataElements().isEmpty()) {
            final MdocClaimFromDTOConverter converter = new MdocClaimFromDTOConverter();
            remoteAttestationPresentationParameters.getDeviceSignedDataElements().forEach(c ->
                    mdocKeyBindingParameters.addDeviceSignedDataElement(converter.apply(c)));
        }
        return mdocKeyBindingParameters;
    }

}
