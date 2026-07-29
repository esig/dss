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
 * Defines a list of attestation types known by the current implementation.
 * NOTE: This type relates to a format of an attestation signed token.
 *
 */
public enum AttestationProfile {

    /**
     * Represents a JWT token, as defined in IETF RFC 7519 "JSON Web Token (JWT)"
     */
    JWT,

    /**
     * Represents a CWT token, as defined in IETF RFC 8392 "CBOR Web Token (CWT)"
     */
    CWT,

    /**
     * Realization of attestation that implements attestation as a JSON Web Signature as specified in IETF RFC 7515,
     * which further profiles a Selective Disclosure JSON Web Token as specified in
     * IETF RFC 9901 "Selective Disclosure for JSON Web Tokens" and in IETF draft-ietf-oauth-sd-jwt-vc.
     */
    SD_JWT_VC,

    /**
     * Realization of attestation that implements attestation built on the data structures defined in ISO/IEC 18013-5.
     */
    ISO_IEC_MDOC,

    /**
     * Realization of attestation based on the JSON-LD (specified in W3C Recommendation:
     * "JSON-LD 1.1. A JSON-based Serialization for Linked Data") serialization of W3C
     * Recommendation (15 May 2025): "Verifiable Credentials Data Model v2.0".
     */
    W3C_VC,

    /**
     * Realization of attestation based on X.509 Attribute certificates as specified in IETF RFC 5755.
     */
    X509_AC

}
