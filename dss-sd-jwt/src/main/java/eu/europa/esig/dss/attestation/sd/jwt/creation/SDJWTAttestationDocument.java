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
package eu.europa.esig.dss.attestation.sd.jwt.creation;

import eu.europa.esig.dss.attestation.common.creation.AttestationDocument;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * SD-JWT implementation of an annotation document, containing the signed JWT and the applicable selective disclosures
 *
 */
public class SDJWTAttestationDocument extends AttestationDocument<SDJWTSelectiveDisclosure> {

    private static final long serialVersionUID = 5572839736743454415L;

    /**
     * Default constructor, instantiating the object from a complete SD Attestation,
     * signed attestation and selective disclosures parts.
     *
     * @param attestationDocument  {@link DSSDocument} attestation with selective disclosures
     * @param signedAttestation    {@link DSSDocument} signed attestation (SDs omitted)
     * @param selectiveDisclosures a list of {@link SDJWTSelectiveDisclosure}s, if any
     */
    public SDJWTAttestationDocument(DSSDocument attestationDocument, DSSDocument signedAttestation,
                                    List<SDJWTSelectiveDisclosure> selectiveDisclosures) {
        super(attestationDocument, signedAttestation, selectiveDisclosures);
    }

}
