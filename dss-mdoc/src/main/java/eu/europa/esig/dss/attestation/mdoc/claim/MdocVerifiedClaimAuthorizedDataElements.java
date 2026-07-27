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

import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Contains all the data elements the key may sign or MAC.
 *
 */
public class MdocVerifiedClaimAuthorizedDataElements extends MdocVerifiedClaimMap {

    private static final long serialVersionUID = -6858102371478589502L;

    private static final Logger LOG = LoggerFactory.getLogger(MdocVerifiedClaimAuthorizedDataElements.class);

    /**
     * Constructor to initialize MdocClaimAuthorizedDataElements from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public MdocVerifiedClaimAuthorizedDataElements(VerifiedClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    /**
     * Gets the map of namespaces and applicable data elements the key is allowed to sign or MAC
     *
     * @return a map of {@link String} namespaces and lists of {@link String} data elements
     */
    public Map<String, List<String>> getDataElements() {
        Map<String, VerifiedClaim> claimMap = getMapValue();
        if (Utils.isMapEmpty(claimMap)) {
            return Collections.emptyMap();
        }
        final Map<String, List<String>> result = new LinkedHashMap<>();
        for (Map.Entry<String, VerifiedClaim> mapEntry : claimMap.entrySet()) {
            List<String> dataElements = result.computeIfAbsent(mapEntry.getKey(), v -> new ArrayList<>());
            if (mapEntry.getValue().isArrayValueType()) {
                mapEntry.getValue().getListValue().forEach(v -> {
                    if (v.isStringValueType()) {
                        dataElements.add(v.getValueAsString());
                    } else {
                        LOG.warn("The entry of DataElementsArray shall be a type of CBOR String!");
                    }
                });
            } else {
                LOG.warn("The value of entry of AuthorizedDataElements shall be a type of CBOR Array!");
            }
        }
        return result;
    }

}
