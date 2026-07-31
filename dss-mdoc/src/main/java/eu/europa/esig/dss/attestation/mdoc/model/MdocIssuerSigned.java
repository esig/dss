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

import eu.europa.esig.dss.attestation.mdoc.creation.MdocIssuerSignedItem;
import eu.europa.esig.dss.cbades.COSESignStructure;

import java.util.List;
import java.util.Map;

/**
 * IssuerSigned contains the mobile security object for issuer data authentication and the data elements
 * protected by issuer data authentication. nameSpaces contains the returned data elements as part of
 * their corresponding namespaces.
 *
 */
public class MdocIssuerSigned {

    /** Map of namespaces and corresponding issuer signed items */
    private Map<String, List<MdocIssuerSignedItem>> namespaces;

    /** Contains the issuer authentication signature */
    private COSESignStructure issuerAuth;

    /**
     * Default constructor
     */
    public MdocIssuerSigned() {
        // empty
    }

    /**
     * Gets a map of namespaces and their corresponding authenticated data
     *
     * @return a map of namespaces and issuer signed items
     */
    public Map<String, List<MdocIssuerSignedItem>> getNamespaces() {
        return namespaces;
    }

    /**
     * Sets a map of namespaces and their corresponding authenticated data
     *
     * @param namespaces a map of namespaces and issuer signed items
     */
    public void setNamespaces(Map<String, List<MdocIssuerSignedItem>> namespaces) {
        this.namespaces = namespaces;
    }

    /**
     * Gets the issuer signature
     *
     * @return {@link COSESignStructure}
     */
    public COSESignStructure getIssuerAuth() {
        return issuerAuth;
    }

    /**
     * Sets the issuer signature
     *
     * @param issuerAuth {@link COSESignStructure}
     */
    public void setIssuerAuth(COSESignStructure issuerAuth) {
        this.issuerAuth = issuerAuth;
    }

}
