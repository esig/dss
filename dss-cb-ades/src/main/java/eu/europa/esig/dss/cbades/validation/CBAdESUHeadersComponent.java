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
package eu.europa.esig.dss.cbades.validation;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;

/**
 * Represents an item of the 'uHeaders' header array
 *
 */
public class CBAdESUHeadersComponent extends CBAdESAttribute {

    private static final long serialVersionUID = 468968604999660231L;

    /** The component in its original representation */
    private final CBORValue component;

    /**
     * Default constructor
     *
     * @param component  {@link CBORValue} original representation of the component
     * @param headerId   {@link CBORValue} header id
     * @param value      {@link CBORValue} value
     * @param identifier {@link CBAdESAttributeIdentifier}
     */
    CBAdESUHeadersComponent(CBORValue component, CBORValue headerId, CBORValue value, CBAdESAttributeIdentifier identifier) {
        super(headerId, value);
        this.component = component;
        this.identifier = identifier;
    }

    /**
     * Builds {@code CBAdESUHeadersComponent} from the 'uHeaders' array entry
     *
     * @param component represents the component of the 'uHeaders' array
     * @param order defines the position number of the component in the 'uHeaders' array
     * @return {@link CBAdESUHeadersComponent}
     * @deprecated since DSS 6.6. Use {@link #build(CBORValue, int)}
     */
    @Deprecated
    public static CBAdESUHeadersComponent build(CBORObject component, int order) {
        if (component != null) {
            return build(component.toCBORValue(), order);
        }
        return null;
    }

    /**
     * Builds {@code CBAdESUHeadersComponent} from the 'uHeaders' array entry
     *
     * @param component {@link CBORValue} represents the component of the 'uHeaders' array
     * @param order defines the position number of the component in the 'uHeaders' array
     * @return {@link CBAdESUHeadersComponent}
     */
    public static CBAdESUHeadersComponent build(CBORValue component, int order) {
        CBORValue cborMap = CBORUtils.parseUHeadersEntry(component);
        if (cborMap != null && cborMap.size() != 0) {
            // one entry is expected
            CBORValue key = cborMap.getKeys().iterator().next();
            CBORValue value = cborMap.get(key);
            CBAdESAttributeIdentifier identifier = CBAdESAttributeIdentifier.build(key, value, order);
            return new CBAdESUHeadersComponent(component, key, value, identifier);
        }
        return null;
    }

    /**
     * Builds the {@code EtsiUComponent} from the given parameters
     *
     * @param headerKey {@link CBORObject} name of the 'uHeaders' array component
     * @param value {@link CBORObject} represents the value of the component
     * @param identifier {@link CBAdESAttributeIdentifier}
     * @return {@link CBAdESUHeadersComponent}
     * @deprecated since DSS 6.6. Use {@link #build(CBORValue, CBORValue, CBAdESAttributeIdentifier)}
     */
    @Deprecated
    public static CBAdESUHeadersComponent build(CBORObject headerKey, CBORObject value, CBAdESAttributeIdentifier identifier) {
        return build(headerKey.toCBORValue(), value.toCBORValue(), identifier);
    }

    /**
     * Builds the {@code EtsiUComponent} from the given parameters
     *
     * @param headerKey {@link CBORValue} name of the 'uHeaders' array component
     * @param value {@link CBORValue} represents the value of the component
     * @param identifier {@link CBAdESAttributeIdentifier}
     * @return {@link CBAdESUHeadersComponent}
     */
    public static CBAdESUHeadersComponent build(CBORValue headerKey, CBORValue value, CBAdESAttributeIdentifier identifier) {
        CBORValue component = createUHeadersComponent(headerKey, value);
        return new CBAdESUHeadersComponent(component, headerKey, value, identifier);
    }

    /**
     * Returns an 'uHeaders' component in the defined representation
     *
     * @param key              {@link CBORValue} header name
     * @param value            {@link CBORValue} object
     * @return {@link CBORValue} 'uHeaders' component
     */
    private static CBORValue createUHeadersComponent(CBORValue key, CBORValue value) {
        return CBOR.bytes(CBOR.map()
                .put(key, value)
                .value().encodeToBytes());
    }

    /**
     * Gets the current component in {@code CBORObject} representation
     *
     * @return {@link CBORValue}
     */
    public CBORValue getComponent() {
        return component;
    }

}
