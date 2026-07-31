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
package eu.europa.esig.dss.ws.attestation.creation.common.converter;

import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocIssuerSignedItem;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTSelectiveDisclosure;
import eu.europa.esig.dss.enumerations.AttestationForm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;

import java.util.Objects;
import java.util.function.Function;

/**
 * Converts a {@code DisclosureDTO} into {@code AttestationDisclosure} of a corresponding format
 */
public class DisclosureFromDTOConverter implements Function<DisclosureDTO, SelectiveDisclosure> {

    /** Attestation type */
    private final AttestationForm attestationForm;

    /**
     * Default constructor
     *
     * @param attestationForm {@link AttestationForm} to create a corresponding implementation of disclosures
     */
    public DisclosureFromDTOConverter(final AttestationForm attestationForm) {
        Objects.requireNonNull(attestationForm, "attestationForm is mandatory!");
        this.attestationForm = attestationForm;
    }

    @Override
    public SelectiveDisclosure apply(DisclosureDTO disclosureDTO) {
        switch (attestationForm) {
            case SD_JWT:
                return new SDJWTSelectiveDisclosure(disclosureDTO.getValue());
            case MDOC:
                return new MdocIssuerSignedItem(disclosureDTO.getNamespace(), disclosureDTO.getDigestId(), Utils.fromBase64(disclosureDTO.getValue()));
            default:
                throw new UnsupportedOperationException(String.format("The attestation Type '%s' is not supported!", attestationForm));
        }
    }

}
