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

import eu.europa.ec.digit.cddl4j.cbor.CBORType;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;

/**
 * Represents a wrapper for a CBOR Object's Tag
 *
 * @deprecated since DSS 6.6. Switch to {@link eu.europa.ec.digit.cddl4j.cbor.CBORValue} instead.
 */
@Deprecated
public class CBORTag extends AbstractCBORObject {

    /**
     * Creates a new CBOR Tag object from the given {@code tag}
     *
     * @param tag {@link CBORValue}
     */
    public CBORTag(final CBORValue tag) {
        super(requireTypeOf(tag, CBORType.TAG));
    }

    /**
     * Returns the Tag value
     *
     * @return long value
     */
    public long getValue() {
        return toCBORValue().getTag().longValue();
    }

}
