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

/**
 * DeviceSigned contains the mdoc authentication structure and the data elements protected by mdoc
 * authentication. nameSpaces contains the returned data elements as part of their corresponding
 * namespaces. nameSpaces is a mandatory element because the element is authenticated using mdoc
 * authentication. The DeviceNameSpaces structure can be an empty structure. The DeviceAuth structure
 * contains either the DeviceSignature or the DeviceMac element, both are defined in 9.1.3.
 *
 */
public class MdocDeviceSigned {

    /** Returned data elements */
    private MdocDeviceNameSpaces deviceNameSpaces;

    /** Contains the device authentication for mdoc authentication  */
    private MdocDeviceAuth deviceAuth;

    /**
     * Default constructor
     */
    public MdocDeviceSigned() {
        // empty
    }

    /**
     * Gets the returned data elements
     *
     * @return {@link MdocDeviceNameSpaces}
     */
    public MdocDeviceNameSpaces getDeviceNameSpaces() {
        return deviceNameSpaces;
    }

    /**
     * Sets the returned data elements
     *
     * @param deviceNameSpaces {@link MdocDeviceNameSpaces}
     */
    public void setDeviceNameSpaces(MdocDeviceNameSpaces deviceNameSpaces) {
        this.deviceNameSpaces = deviceNameSpaces;
    }

    /**
     * Gets the device authentication
     *
     * @return {@link MdocDeviceAuth}
     */
    public MdocDeviceAuth getDeviceAuth() {
        return deviceAuth;
    }

    /**
     * Sets the device authentication
     *
     * @param deviceAuth {@link MdocDeviceAuth}
     */
    public void setDeviceAuth(MdocDeviceAuth deviceAuth) {
        this.deviceAuth = deviceAuth;
    }

}
