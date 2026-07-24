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
 * Contains a list of common constants used for reading and processing an mdoc content
 *
 */
public class MdocConstants {

    /**
     * Utils class
     */
    private MdocConstants() {
        // singleton
    }

    /* List of supported mdoc document types */

    /** mdoc document type as defined in ISO/IEC 18013-5 */
    public static final String ISO18013_5_MDL_DOC_TYPE = "org.iso.18013.5.1.mDL";

    /** mdoc document type as defined in ISO/IEC 23220-2 */
    public static final String ISO23220_1_MID_DOC_TYPE = "org.iso.23220.1.mID";

    /** PID Rulebook, ISO/IEC 18013-5-compliant encoding of PID mdoc document type  */
    public static final String EUDI_PID_DOC_TYPE = "eu.europa.ec.eudi.pid.1";

    /* Known namespaces */

    /** Namespace for the data elements defined in section 6 of ETSI TS 119 472-1  */
    public static final String ETSI_19472_1_NAMESPACE = "org.etsi.01947201.010101";

    /** Namespace for the data elements defined in section 7.1 of ISO/IEC 18013-5  */
    public static final String ISO18013_5_NAMESPACE = "org.iso.18013.5.1";

    /** Namespace for the data elements defined in section 6.3 of ISO/IEC 23220-2  */
    public static final String ISO23220_1_NAMESPACE = "org.iso.23220.1";

    /** PID Rulebook, ISO/IEC 18013-5-compliant encoding of PID namespace */
    public static final String EUDI_PID_NAMESPACE = "eu.europa.ec.eudi.pid.1";

    /* mdoc MobileSecurityObject parameters */

    /** List of individual data elements for a key usage */
    public static final String DATA_ELEMENTS = "dataElements";

    /** The public part of the key pair used for mdoc authentication */
    public static final String DEVICE_KEY = "deviceKey";

    /** The mdoc authentication public key and information related to this key */
    public static final String DEVICE_KEY_INFO = "deviceKeyInfo";

    /** The device authentication */
    public static final String DEVICE_AUTHENTICATION = "DeviceAuthentication";

    /** Message digest algorithm used */
    public static final String DIGEST_ALGORITHM = "digestAlgorithm";

    /** docType as used in Documents */
    public static final String DOC_TYPE = "docType";

    /** The timestamp at which the issuing authority infrastructure expects to re-sign the MSO (tdate) */
    public static final String EXPECTED_UPDATE = "expectedUpdate";

    /** Authorized scope of key usage */
    public static final String KEY_AUTHORIZATIONS = "keyAuthorizations";

    /** Extra info about the key */
    public static final String KEY_INFO = "keyInfo";

    /** List of authorized namespaces for a key usage */
    public static final String NAMESPACES = "nameSpaces";

    /** The timestamp at which the MSO signature was created (tdate) */
    public static final String SIGNED = "signed";

    /** Information related to the validity of the MSO and its signature */
    public static final String VALIDITY_INFO = "validityInfo";

    /** The timestamp before which the MSO is not yet valid (tdate) */
    public static final String VALID_FROM = "validFrom";

    /** The timestamp after which the MSO is no longer valid (tdate) */
    public static final String VALID_UNTIL = "validUntil";

    /** Digests of all data elements per namespace */
    public static final String VALUE_DIGEST = "valueDigests";

    /** Version of the MobileSecurityObject */
    public static final String VERSION = "version";

    // Currently referenced in draft-ietf-oauth-revocation-list-19, but may be included in MobileSecurityObject

    /** Specifies a CBOR Object that contains at least one reference to a revocation mechanism */
    public static final String STATUS = "revocation";

    /** Specifies a CBOR Object that contains at least one reference to a revocation mechanism. Long representation. */
    public static final CBORObject STATUS_LONG = CBORObjectFactory.toCBORObject(65535L);

    /** Specifies a CBOR Object that contains a reference to a Status List Token */
    public static final String STATUS_LIST = "status_list";

    /** A non-negative Integer that represents the index to check for revocation information for the current Token */
    public static final String STATUS_IDX = "idx";

    /** A non-negative Integer that represents the index to check for revocation information for the current Token */
    public static final String STATUS_INDEX = "index";

    /** String value that identifies the Status List Token containing the revocation information for the Token */
    public static final String STATUS_URI = "uri";

    /** An identifier of the type of the revocation information provided by the service */
    public static final String STATUS_TYPE = "type";

    /** Purpose of the revocation entry claim */
    public static final String STATUS_PURPOSE = "purpose";

    // status_list and identifier_list elements currently defined in the draft of amendments to EU Implementing Acts

    /** A certificate used to sign the top-level certificate in the x5chain element in the MSO revocation list structure */
    public static final String STATUS_CERTIFICATE = "certificate";

    /** Specifies a CBOR Object that contains a reference to an Identifier List */
    public static final String IDENTIFIER_LIST = "identifier_list";

    /** Unique identifier of the token */
    public static final String IDENTIFIER_ID = "id";

    /** String value that identifies the Identifier List containing the revocation information for the Token */
    public static final String IDENTIFIER_URI = "uri";

    /** A certificate used to sign the top-level certificate in the x5chain element in the MSO revocation list structure */
    public static final String IDENTIFIER_CERTIFICATE = "certificate";

}
