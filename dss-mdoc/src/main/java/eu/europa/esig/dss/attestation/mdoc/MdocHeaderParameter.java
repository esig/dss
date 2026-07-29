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
package eu.europa.esig.dss.attestation.mdoc;

import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory;

/**
 * Contains a list of mdoc header parameters supported by the implementation
 *
 */
public enum MdocHeaderParameter {

    /* mdoc message header names */

    /** For unreturned documents, optional error codes */
    DOCUMENT_ERRORS("documentErrors"),

    /** Returned documents */
    DOCUMENTS("documents"),

    /** Status code */
    STATUS("status"),

    /** Version of the structure */
    VERSION("version"),

    /* Document type */

    /** Returned data elements signed by the mdoc */
    DEVICE_SIGNED("deviceSigned"),

    /** Document type returned */
    DOC_TYPE("docType"),

    /** Errors for the returned document */
    ERRORS("errors"),

    /** Returned data elements signed by the issue */
    ISSUER_SIGNED("issuerSigned"),

    /* Issuer signed */

    /** Digest ID for issuer data authentication */
    DIGEST_ID("digestID"),

    /** Data element identifier */
    ELEMENT_IDENTIFIER("elementIdentifier"),

    /** Data element value */
    ELEMENT_VALUE("elementValue"),

    /** Contains the mobile security object (MSO) for issuer data authentication */
    ISSUER_AUTH("issuerAuth"),

    /** Returned data elements */
    NAMESPACES("nameSpaces"),

    /** Random value for issuer data authentication */
    RANDOM("random"),

    /* Device signed */

    /** Contains the device authentication for mdoc authentication  */
    DEVICE_AUTH("deviceAuth"),

    /** COSE_Mac0 signature  */
    DEVICE_MAC("deviceMac"),

    /** COSE_Sign1 signature  */
    DEVICE_SIGNATURE("deviceSignature");

    /** String key */
    private final String stringKey;

    /** CBOR key */
    private final CBORObject cborKey;

    /**
     * Utils class
     */
    MdocHeaderParameter(final String stringKey) {
        this.stringKey = stringKey;
        this.cborKey = CBORObjectFactory.toCBORObject(stringKey);
    }

    /**
     * Gets representation of the header parameter in a form of CBOR object
     *
     * @return {@link CBORObject}
     */
    public CBORObject cbor() {
        return cborKey;
    }

    @Override
    public String toString() {
        return stringKey;
    }

}
