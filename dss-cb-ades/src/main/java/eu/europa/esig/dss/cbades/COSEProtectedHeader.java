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

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.spi.DSSUtils;

/**
 * Represents a COSE protected header structure
 *
 */
public class COSEProtectedHeader extends COSEHeader {

    /**
     * Constructor to create an empty protected header
     */
    public COSEProtectedHeader() {
        super();
    }

    /**
     * Creates a COSEProtectedHeader from a serialized map
     *
     * @param cborByteString byte array containing an empty or serialized map
     */
    public COSEProtectedHeader(final byte[] cborByteString) {
        super(cborByteString);
    }

    /**
     * Creates a COSEProtectedHeader from a serialized map
     *
     * @param cborByteString byte array containing an empty or serialized map
     */
    public COSEProtectedHeader(final CBORValue cborByteString) {
        this(cborByteString.asBytes());
    }

    /**
     * Gets the protected header as a CBOR byte string
     *
     * @return {@link CBORValue}
     */
    public CBORValue asByteString() {
        /*
         * RFC 9052 "3. Header Parameters"
         *
         * protected : Senders SHOULD encode a zero-length map as a zero-length
         * byte string rather than as a zero-length map (encoded as h'a0'). The
         * zero-length byte string encoding is preferred, because it is both
         * shorter and the version used in the serialization structures for
         * cryptographic computation.
         */
        if (isEmpty()) {
            return CBOR.bytes(DSSUtils.EMPTY_BYTE_ARRAY);
        }
        return CBOR.bytes(CBORUtils.serializeCbor(getValue()));
    }

}
