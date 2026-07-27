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
package eu.europa.esig.dss.enumerations;

/**
 * Defines a list of format types on which supported attestation presentations may be based.
 * NOTE: This type relates to a format of an attestation presentation document.
 *
 */
public enum AttestationDocumentFormat {

    /**
     * Represents a JWT token, as defined in IETF RFC 7519 "JSON Web Token (JWT)"
     */
    JWT,

    /**
     * Represents a CWT token, as defined in IETF RFC 8392 "CBOR Web Token (CWT)"
     */
    CWT,

    /**
     * Represents an IETF RFC 9901 "Selective Disclosure for JSON Web Tokens" token.
     */
    SD_JWT,

    /**
     * Represents a DeviceResponse mdoc structure as per ISO/IEC 18013-5 "8.3.2.1.2.2 Device retrieval mdoc response"
     */
    MDOC_DEVICE_RESPONSE,

    /**
     * Represents an IssuerSigned mdoc structure as per ISO/IEC 18013-5 "8.3.2.1.2.2 Device retrieval mdoc response"
     */
    MDOC_ISSUER_SIGNED,

    /**
     * Realization of attestation based on X.509 Attribute certificates as specified in IETF RFC 5755.
     */
    X509_AC

}
