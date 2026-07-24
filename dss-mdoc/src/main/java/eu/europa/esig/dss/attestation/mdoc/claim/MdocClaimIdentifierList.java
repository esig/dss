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
package eu.europa.esig.dss.attestation.mdoc.claim;

import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.model.attestation.claim.ClaimByteString;
import eu.europa.esig.dss.model.attestation.claim.ClaimIdentifierList;
import eu.europa.esig.dss.model.attestation.claim.ClaimMap;
import eu.europa.esig.dss.model.attestation.claim.ClaimString;

/**
 * Represents an IdentifierListInfo object as defined in ETSI TS 119 472-1 (currently in IA draft only)
 * 
 */
public class MdocClaimIdentifierList extends MdocClaimMap implements ClaimIdentifierList {

    private static final long serialVersionUID = -8431629611618058461L;

    /**
     * Constructor to initialize MdocClaimIdentifierList from a ClaimMap
     *
     * @param value {@link ClaimMap}
     */
    public MdocClaimIdentifierList(ClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public ClaimByteString getIdentifier() {
        return getAsByteString(MdocConstants.IDENTIFIER_ID);
    }

    @Override
    public ClaimString getUri() {
        return getAsString(MdocConstants.IDENTIFIER_URI);
    }

    @Override
    public ClaimByteString getCertificate() {
        return getAsByteString(MdocConstants.IDENTIFIER_CERTIFICATE);
    }

}
