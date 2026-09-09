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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.attestation.mdoc.MdocHeaderParameter;

import java.util.Objects;

/**
 * Default implementation of a {@code eu.europa.esig.dss.attestation.mdoc.creation.MdocDisclosureBuilder}
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
    public MdocIssuerSignedItem build(MdocClaim claim) {
        Objects.requireNonNull(claim, "MdocClaim cannot be null!");

        final CBORValue issuerSignedItem = CBOR.map()
                .put(MdocHeaderParameter.DIGEST_ID.toString(), claim.getDigestId())
                .put(MdocHeaderParameter.RANDOM.toString(), claim.getSalt())
                .put(MdocHeaderParameter.ELEMENT_IDENTIFIER.toString(), claim.getName())
                .put(MdocHeaderParameter.ELEMENT_VALUE.toString(), claim.getValueAsCbor())
                .value();

        if (claim.isVoid()) {
            return new MdocIssuerSignedItem(claim.getDigestId(), CBORTags.encodedCbor(issuerSignedItem.encodeToBytes()));
        } else {
            return new MdocIssuerSignedItem(claim.getNamespace(), claim.getDigestId(), CBORTags.encodedCbor(issuerSignedItem.encodeToBytes()));
        }
    }

}
