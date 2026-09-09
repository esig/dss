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

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;

/**
 * Factory to create a {@code eu.europa.esig.dss.cbades.cbor.CBORObject} from a value
 *
 * @deprecated since DSS 6.6. Please use {@link CBORValueFactory} instead.
 */
@Deprecated
public class CBORObjectFactory {

    /**
     * Default constructor
     */
    private CBORObjectFactory() {
        // empty
    }

    /**
     * Instantiates a new CBOR object from the given object
     *
     * @param object object to covert
     * @return {@link CBORObject}
     * @deprecated since DSS 6.6. Please use {@link CBORValueFactory#toCBORValue(Object)}.
     */
    @Deprecated
    public static CBORObject toCBORObject(Object object) {
        if (object == null) {
            return null;
        }
        if (object instanceof CBORObject) {
            return (CBORObject) object;
        }
        CBORValue cborValue = CBORValueFactory.toCBORValue(object);
        switch (cborValue.getType()) {
            case MAP:
                return new CBORMap(cborValue);
            case ARRAY:
                return new CBORArray(cborValue);
            case BYTE_STRING:
                return new CBORByteString(cborValue);
            case TAG:
                CBORValue taggedValue = cborValue.getTaggedValue();
                CBORObject taggedObject = toCBORObject(taggedValue);
                taggedObject.setTag(cborValue.getTag().longValue());
                return taggedObject;
            case NULL:
                return new CBORNull(cborValue);
            default:
                return new CBORSimpleObject(cborValue);
        }
    }

}
