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
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimArray;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;

/**
 * Contains all the namespaces and/or data elements the key may sign or MAC.
 *
 */
public class MdocVerifiedClaimKeyAuthorizations extends MdocVerifiedClaimMap {

    private static final long serialVersionUID = -6321124455458258021L;

    /**
     * Constructor to initialize MdocClaimKeyAuthorizations from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public MdocVerifiedClaimKeyAuthorizations(VerifiedClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    /**
     * Gets a list of namespaces the key is authorized to sign or MAC
     *
     * @return {@link MdocVerifiedClaimAuthorizedNameSpaces}
     */
    public MdocVerifiedClaimAuthorizedNameSpaces getAuthorizedNamespaces() {
        VerifiedClaimArray namespaces = getAsArray(MdocConstants.NAMESPACES);
        if (namespaces != null) {
            return new MdocVerifiedClaimAuthorizedNameSpaces(namespaces);
        }
        return null;
    }

    /**
     * Gets a map of namespaces and applicable data elements the key is allowed to sign or MAC
     *
     * @return {@link MdocVerifiedClaimAuthorizedNameSpaces}
     */
    public MdocVerifiedClaimAuthorizedDataElements getAuthorizedDataElements() {
        VerifiedClaimMap dataElements = getAsMap(MdocConstants.DATA_ELEMENTS);
        if (dataElements != null) {
            return new MdocVerifiedClaimAuthorizedDataElements(dataElements);
        }
        return null;
    }

}
