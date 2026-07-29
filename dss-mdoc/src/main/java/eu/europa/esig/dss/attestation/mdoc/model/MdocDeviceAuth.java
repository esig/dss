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

import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.cbor.CBORArray;

/**
 * The DeviceAuth structure contains either the DeviceSignature or the DeviceMac element, both are defined in 9.1.3.
 *
 */
public class MdocDeviceAuth {

    /** Contains a key binding signature */
    private COSESignStructure deviceSignature;

    /** Contains a MAC authentication signature */
    private CBORArray deviceMac;

    /**
     * Default constructor
     */
    public MdocDeviceAuth() {
        // empty
    }

    /**
     * Gets a device signature
     *
     * @return {@link COSESignStructure}
     */
    public COSESignStructure getDeviceSignature() {
        return deviceSignature;
    }

    /**
     * Sets a device signature
     *
     * @param deviceSignature {@link COSESignStructure}
     */
    public void setDeviceSignature(COSESignStructure deviceSignature) {
        this.deviceSignature = deviceSignature;
    }

    /**
     * Gets a device MAC structure
     *
     * @return {@link CBORArray}
     */
    public CBORArray getDeviceMac() {
        return deviceMac;
    }

    /**
     * Sets a device MAC structure
     *
     * @param deviceMac {@link CBORArray}
     */
    public void setDeviceMac(CBORArray deviceMac) {
        this.deviceMac = deviceMac;
    }

}
