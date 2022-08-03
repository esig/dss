/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTrustedListSignatureParameters;

/**
 * DTO for getDataToSign(..) method call for an XML Trusted List creation.
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation).
 *
 */
public class DataToSignTrustedListDTO {

    /** Document to be signed */
    private RemoteDocument trustedList;

    /** The signature parameters */
    private RemoteTrustedListSignatureParameters parameters;

    /**
     * Empty constructor
     */
    public DataToSignTrustedListDTO() {
        // empty
    }

    /**
     * Default constructor with customizable parameters
     *
     * @param trustedList
     *                  {@link RemoteDocument} XML Trusted List to be signed
     * @param parameters
     *                  {@link RemoteTrustedListSignatureParameters} customizable signature parameters
     */
    public DataToSignTrustedListDTO(RemoteDocument trustedList, RemoteTrustedListSignatureParameters parameters) {
        this.trustedList = trustedList;
        this.parameters = parameters;
    }

    /**
     * Gets an XML Trusted List to be signed
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getTrustedList() {
        return trustedList;
    }

    /**
     * Sets an XML Trusted List to be signed
     *
     * @param trustedList {@link RemoteDocument}
     */
    public void setTrustedList(RemoteDocument trustedList) {
        this.trustedList = trustedList;
    }

    /**
     * Gets signature parameters for XML Trusted List signing
     *
     * @return {@link RemoteTrustedListSignatureParameters}
     */
    public RemoteTrustedListSignatureParameters getParameters() {
        return parameters;
    }

    /**
     * Sets signature parameters for XML Trusted List signing
     *
     * @param parameters {@link RemoteTrustedListSignatureParameters}
     */
    public void setParameters(RemoteTrustedListSignatureParameters parameters) {
        this.parameters = parameters;
    }

}
