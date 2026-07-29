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
package eu.europa.esig.dss.attestation.mdoc.model;

import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.spi.exception.IllegalInputException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents a structure of the DeviceNameSpacesBytes element.
 *
 */
public class MdocDeviceNameSpaces {

    /** Original bytes */
    private final CBORByteString deviceNameSpaceBytes;

    /** Parsed map of namespaces and corresponding issuer signed items */
    private final Map<String, CBORMap> namespaces;

    /**
     * Default constructor
     *
     * @param deviceNameSpaceBytes {@link CBORByteString} representing DeviceNameSpacesBytes
     */
    public MdocDeviceNameSpaces(final CBORByteString deviceNameSpaceBytes) {
        this.deviceNameSpaceBytes = deviceNameSpaceBytes;
        this.namespaces = parseNameSpaces(deviceNameSpaceBytes);
    }

    private Map<String, CBORMap> parseNameSpaces(CBORByteString deviceNameSpaceBytes) {
        CBORMap deviceNameSpaces = new CBORMap(deviceNameSpaceBytes);
        if (deviceNameSpaces.isEmpty()) {
            // can be empty
            return Collections.emptyMap();
        }

        final Map<String, CBORMap> namespaces = new HashMap<>();
        for (CBORObject mapKey : deviceNameSpaces.getKeys()) {
            if (!mapKey.isUnicodeString()) {
                throw new IllegalInputException("NameSpace shall be of unicode string type!");
            }
            String namespace = mapKey.getValueAsString();
            CBORObject deviceSignedItems = deviceNameSpaces.getHeader(mapKey);
            if (!deviceSignedItems.isMap()) {
                throw new IllegalInputException("DeviceSignedItems shall be of Map type!");
            }
            namespaces.put(namespace, (CBORMap) deviceSignedItems);
        }
        return namespaces;
    }

    /**
     * Gets the original extracted DeviceNameSpacesBytes
     *
     * @return {@link CBORByteString}
     */
    public CBORByteString getDeviceNameSpaceBytes() {
        return deviceNameSpaceBytes;
    }

    /**
     * Gets a parsed map of namespaces and their corresponding values
     *
     * @return a map of namespaces
     */
    public Map<String, CBORMap> getNamespaces() {
        return namespaces;
    }

}
