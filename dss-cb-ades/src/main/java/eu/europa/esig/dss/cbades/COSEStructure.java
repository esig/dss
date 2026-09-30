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
import eu.europa.esig.dss.enumerations.COSESignatureType;

/**
 * Represents a shared interface for COSE signature structure objects defined in RFC 9052 and
 * COSE counter signatures defined in RFC 9338
 */
public interface COSEStructure {

    /**
     * Builds an RFC 9052 COSE signature structure
     *
     * @return serialized byte array
     */
    byte[] serialize();

    /**
     * Gets the COSE signature context
     *
     * @return {@link COSESignatureType}
     */
    COSESignatureType getContext();

    /**
     * Serialized the current COSE counter signature structure to a CBOR Value
     *
     * @return {@link eu.europa.ec.digit.cddl4j.cbor.CBORValue}
     */
    CBORValue toCBORValue();

}
