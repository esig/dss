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
package eu.europa.esig.dss.cbades;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORObject;

/**
 * Represents a common interface for COSE counter-signature structure objects defined in RFC 9338
 *
 */
public interface COSECounterSignStructure extends COSEStructure {

    /**
     * Gets whether the signature structure is encoded as tagged
     *
     * @return TRUE if the signature structure is encoded as tagged, FALSE in case of untagged
     */
    boolean isTagged();

    /**
     * Gets the master signature structure
     *
     * @return {@link COSEStructure}
     */
    COSEStructure getMasterSignature();

    /**
     * Serialized the current COSE counter signature structure to a CBOR Object
     *
     * @return {@link CBORObject}
     * @deprecated since DSS 6.6. Use {@link #toCBORValue()}.
     */
    @Deprecated
    CBORObject toCBORObject();

    /**
     * Serialized the current COSE counter signature structure to a CBOR Value
     *
     * @return {@link eu.europa.ec.digit.cddl4j.cbor.CBORValue}
     */
    CBORValue toCBORValue();

}
