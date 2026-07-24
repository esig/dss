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

import java.io.Serializable;
import java.util.Map;

/**
 * This class represents a Document as defined in ISO 18013-5 "8.3.2.1.2.2 Device retrieval mdoc response".
 *
 */
public class MdocDocument implements Serializable {

    private static final long serialVersionUID = 266513745883863248L;

    /**
     * Represents a type of the returned document
     */
    private String docType;

    /**
     * Returned data elements signed by the issuer
     */
    private MdocIssuerSigned issuerSigned;

    /**
     * Returned data elements signed by the mdoc
     */
    private MdocDeviceSigned deviceSigned;

    /**
     * Returned errors map
     */
    private Map<String, MdocErrorItems> errors;

    /**
     * Default constructor
     */
    public MdocDocument() {
        // empty
    }

    /**
     * Gets the type of the returned document
     *
     * @return {@link String}
     */
    public String getDocType() {
        return docType;
    }

    /**
     * Sets the type of the returned document
     *
     * @param docType {@link String}
     */
    public void setDocType(String docType) {
        this.docType = docType;
    }

    /**
     * Gets the returned data elements signed by the issuer
     *
     * @return {@link MdocIssuerSigned}
     */
    public MdocIssuerSigned getIssuerSigned() {
        return issuerSigned;
    }

    /**
     * Sets the returned data elements signed by the issuer
     *
     * @param issuerSigned {@link MdocIssuerSigned}
     */
    public void setIssuerSigned(MdocIssuerSigned issuerSigned) {
        this.issuerSigned = issuerSigned;
    }

    /**
     * Gets the returned data elements signed by the mdoc
     *
     * @return {@link MdocDeviceSigned}
     */
    public MdocDeviceSigned getDeviceSigned() {
        return deviceSigned;
    }

    /**
     * Sets the returned data elements signed by the mdoc
     *
     * @param deviceSigned {@link MdocDeviceSigned}
     */
    public void setDeviceSigned(MdocDeviceSigned deviceSigned) {
        this.deviceSigned = deviceSigned;
    }

    /**
     * Gets a map of occurred errors (optional)
     *
     * @return a map between element namespaces and corresponding errors
     */
    public Map<String, MdocErrorItems> getErrors() {
        return errors;
    }

    /**
     * Sets a map of occurred errors (optional)
     *
     * @param errors a map between element namespaces and corresponding errors
     */
    public void setErrors(Map<String, MdocErrorItems> errors) {
        this.errors = errors;
    }

}
