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
package eu.europa.esig.dss.cbades.cbor;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORType;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.spi.DSSUtils;

/**
 * A wrapper for a CBOR ByteString object implementation
 *
 * @deprecated since DSS 6.6. Switch to {@link eu.europa.ec.digit.cddl4j.cbor.CBORValue} instead.
 */
@Deprecated
public class CBORByteString extends AbstractCBORObject {

    /**
     * Constructor to create an empty CBOR ByteString object
     */
    public CBORByteString() {
        this(DSSUtils.EMPTY_BYTE_ARRAY);
    }

    /**
     * Constructor to create a CBOR ByteString object from a byte array
     *
     * @param byteArray a byte array
     */
    public CBORByteString(final byte[] byteArray) {
        this(CBOR.bytes(byteArray));
    }

    /**
     * Constructor to create a CBOR ByteString object from a {@code ByteString} implementation
     *
     * @param byteString {@link CBORValue}
     */
    public CBORByteString(final CBORValue byteString) {
        super(requireTypeOf(byteString, CBORType.BYTE_STRING));
    }

    @Override
    public byte[] getValueAsBytes() {
        return getCBORValue().asBytes();
    }

}
