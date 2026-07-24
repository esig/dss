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

import eu.europa.esig.dss.model.attestation.claim.Claim;
import eu.europa.esig.dss.model.attestation.claim.ClaimArray;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Contains all the namespaces the key may sign or MAC.
 *
 */
public class MdocClaimAuthorizedNameSpaces extends MdocClaimArray {

    private static final long serialVersionUID = 1383542498839236404L;

    private static final Logger LOG = LoggerFactory.getLogger(MdocClaimAuthorizedNameSpaces.class);

    /**
     * Constructor to initialize MdocClaimAuthorizedNameSpaces from a ClaimMap
     *
     * @param value {@link ClaimArray}
     */
    public MdocClaimAuthorizedNameSpaces(ClaimArray value) {
        super(value.getName(), value.getNamespace(), value.getListValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    /**
     * Gets a list of namespaces the key is allowed to sign or MAC
     *
     * @return a list of {@link String} namespaces
     */
    public List<String> getNamespaces() {
        List<Claim> listValue = getListValue();
        if (Utils.isCollectionEmpty(listValue)) {
            return Collections.emptyList();
        }
        final List<String> namespaces = new ArrayList<>();
        for (Claim namespaceClaim : listValue) {
            if (namespaceClaim.isStringValueType()) {
                namespaces.add(namespaceClaim.getValueAsString());
            } else {
                LOG.warn("The entry of AuthorizedNameSpaces shall be a type of CBOR String!");
            }
        }
        return namespaces;
    }

}
