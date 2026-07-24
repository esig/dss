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
package eu.europa.esig.dss.eaa.mdoc.creation;

import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.eaa.mdoc.MdocHeaderParameter;

import java.util.Objects;

/**
 * Default implementation of a {@code eu.europa.esig.dss.eaa.mdoc.creation.MdocDisclosureBuilder}
 * use to build a IssuerSignedItemBytes structure.
 * Example of a produced item:
 * {@code
 *   24(<< {"digestID": 1, "random": h'87A1148380494EF', "elementIdentifier": "given_name", "elementValue": "John"} >>)
 * }
 */
public class DefaultMdocSelectiveDisclosureBuilder implements MdocSelectiveDisclosureBuilder {

    /**
     * Default constructor
     */
    public DefaultMdocSelectiveDisclosureBuilder() {
        // empty
    }

    @Override
    public MdocSelectiveDisclosure build(MdocClaim claim) {
        Objects.requireNonNull(claim, "MdocEAAClaim cannot be null!");

        final CBORMap issuerSignedItem = new CBORMap();
        issuerSignedItem.put(MdocHeaderParameter.DIGEST_ID.toString(), claim.getDigestId());
        issuerSignedItem.put(MdocHeaderParameter.RANDOM.toString(), claim.getSalt());
        issuerSignedItem.put(MdocHeaderParameter.ELEMENT_IDENTIFIER.toString(), claim.getName());
        issuerSignedItem.put(MdocHeaderParameter.ELEMENT_VALUE.toString(), claim.getValueAsCbor());

        if (claim.isVoid()) {
            return new MdocSelectiveDisclosure(claim.getDigestId(), CBORUtils.toCborBtsrWrappedTagged(issuerSignedItem));
        } else {
            return new MdocSelectiveDisclosure(claim.getNamespace(), claim.getDigestId(), CBORUtils.toCborBtsrWrappedTagged(issuerSignedItem));
        }
    }

}
