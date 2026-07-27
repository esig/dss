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

import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.attestation.common.creation.SelectiveDisclosure;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTSelectiveDisclosure;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocSelectiveDisclosure;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.DisclosureDTO;

import java.util.function.Function;

/**
 * Converts a {@code AttestationDisclosure} into {@code DisclosureDTO} of a corresponding format
 *
 */
public class DisclosureToDTOConverter implements Function<SelectiveDisclosure, DisclosureDTO> {

    /**
     * Default constructor
     */
    public DisclosureToDTOConverter() {
        super();
    }

    @Override
    public DisclosureDTO apply(SelectiveDisclosure disclosureDTO) {
        if (disclosureDTO instanceof SDJWTSelectiveDisclosure) {
            SDJWTSelectiveDisclosure sdjwtSelectiveDisclosure = (SDJWTSelectiveDisclosure) disclosureDTO;
            return new DisclosureDTO(sdjwtSelectiveDisclosure.getDisclosure());
        } else if (disclosureDTO instanceof MdocSelectiveDisclosure) {
            MdocSelectiveDisclosure mdocAttestationDisclosure = (MdocSelectiveDisclosure) disclosureDTO;
            String disclosureValueB64 = Utils.toBase64(CBORUtils.serializeCborObject(mdocAttestationDisclosure.getIssuerSignedItemBytes()));
            return new DisclosureDTO(mdocAttestationDisclosure.getNamespace(), mdocAttestationDisclosure.getDigestId(), disclosureValueB64);
        } else {
            throw new UnsupportedOperationException(String.format(
                    "The attestation Disclosure Type '%s' is not supported!", disclosureDTO.getClass().getSimpleName()));
        }
    }

}
