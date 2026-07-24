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

import eu.europa.esig.dss.attestation.common.creation.KeyBindingParameters;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of {@link KeyBindingParameters} for ISO/IEC 18013-5 mdoc EAA.
 */
public class MdocKeyBindingParameters implements KeyBindingParameters, MdocDeviceSignedParameters {

    /** The session transcript to use for the creation of the key binding signature */
    private DSSDocument sessionTranscript;

    /** Doc type to use for the key binding signature, the value should be the same as the one in {@link MdocPayloadParameters} */
    private String docType;

    /** The list of device signed data elements */
    private final List<MdocClaim> deviceSignedDataElements = new ArrayList<>();

    /**
     * Default constructor
     */
    public MdocKeyBindingParameters() {
        // empty
    }

    /**
     * Gets SessionTranscript for generation of a detached paylaod of the mdoc deviceAuth signature
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getSessionTranscript() {
        return sessionTranscript;
    }

    /**
     * Sets SessionTranscript structure for generation of a detached paylaod of the mdoc deviceAuth signature
     *
     * @param sessionTranscript {@link DSSDocument}
     */
    public void setSessionTranscript(final DSSDocument sessionTranscript) {
        this.sessionTranscript = sessionTranscript;
    }

    /**
     * Gets the document type
     *
     * @return {@link String}
     */
    public String getDocType() {
        return docType;
    }

    /**
     * Sets the document type. Shall be the same as the docType of the EAA.
     *
     * @param docType {@link String}
     */
    public void setDocType(final String docType) {
        this.docType = docType;
    }

    /**
     * Adds a data element to be incorporated within DeviceSigned.nameSpaces structure
     *
     * @param deviceSignedDataElement {@link MdocClaim}
     */
    public void addDeviceSignedDataElement(final MdocClaim deviceSignedDataElement) {
        deviceSignedDataElements.add(deviceSignedDataElement);
    }

    /**
     * Adds a data element to be incorporated within DeviceSigned.nameSpaces structure
     *
     * @param namespace {@link String}
     * @param name {@link String}
     * @param value {@link Object}
     */
    public void addDeviceSignedDataElement(final String namespace, final String name, final Object value) {
        deviceSignedDataElements.add(MdocClaim.create(namespace, name, value));
    }

    @Override
    public List<MdocClaim> getDeviceSignedDataElements() {
        return deviceSignedDataElements;
    }

}
