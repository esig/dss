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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;

/**
 * Default implementation of {@link MdocDeviceNameSpacesBuilder}
 */
public class DefaultMdocDeviceNameSpacesBuilder implements MdocDeviceNameSpacesBuilder {

    /**
     * Default constructor
     */
    public DefaultMdocDeviceNameSpacesBuilder(){
        //empty
    }

    @Override
    public CBORByteString buildDeviceNameSpacesBytes(final MdocDeviceSignedParameters mdocDeviceSignedParameters) {
        Map<String, List<MdocClaim>> groupedClaims = mdocDeviceSignedParameters.getDeviceSignedDataElements()
                .stream()
                .collect(Collectors.groupingBy(MdocClaim::getNamespace, LinkedHashMap::new, Collectors.toList()));

        CBORMap deviceNameSpaces = new CBORMap();

        for (Map.Entry<String, List<MdocClaim>> entry : groupedClaims.entrySet()) {
            CBORMap map = new CBORMap();
            for (MdocClaim claim : entry.getValue()) {
                CBORObject object = CBORObjectFactory.toCBORObject(claim.getValue());
                map.put(claim.getName(), object);
            }

            deviceNameSpaces.put(entry.getKey(), map);
        }

        return CBORUtils.toCborBtsrWrappedTagged(deviceNameSpaces);
    }
}
