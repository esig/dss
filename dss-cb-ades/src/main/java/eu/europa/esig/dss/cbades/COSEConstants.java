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
package eu.europa.esig.dss.cbades;

/**
 * Utils class containing RFC 9052 and ETSI TS 119 152 constants
 *
 */
public final class COSEConstants {

    /* RFC 9052 COSE structure */

    /** COSE_Sign. CBOR Tag '98' */
    public static final long COSE_SIGN_TAG = 98;

    /** COSE_Sign1. CBOR Tag '18' */
    public static final long COSE_SIGN1_TAG = 18;

    /* RFC 9338 Header parameters */

    /** COSE_Countersignature. CBOR Tag '19' */
    public static final long COSE_COUNTERSIGNATURE_TAG = 19;

    /* Subtype keys */

    /** NotCertifiedItem mediaType: String identifying the type of claimed attributes or signed assertions. Array position '0' */
    public static final int NOT_CERTIFIED_ITEM_MEDIA_TYPE = 0;

    /** NotCertifiedItem encoding: String identifying the encoding of claimed attributes or signed assertions. Array position '1' */
    public static final int NOT_CERTIFIED_ITEM_ENCODING = 1;

    /** NotCertifiedItem qVals: Array with the claimed attributes or signed assertions. Array position '2' */
    public static final int NOT_CERTIFIED_ITEM_QVALS = 2;

    /** DigAlgVal hashAlg. Array position '0' */
    public static final int DIG_ALG_VAL_HASH_ALG = 0;

    /** DigAlgVal hashValue. Array position '1' */
    public static final int DIG_ALG_VAL_HASH_VALUE = 1;

    /** COSE_CertHash hashAlg. Array position '0' */
    public static final int COSE_CERT_HASH_ALG = 0;

    /** COSE_CertHash hashValue. Array position '1' */
    public static final int COSE_CERT_HASH_VALUE = 1;

    /* COSE_Key */

    /** COSE_Key 'kty'. Array position '1' */
    public static final long COSE_KEY_KTY = 1;

    /** COSE_Key 'kid'. Array position '2' */
    public static final long COSE_KEY_KID = 2;

    /** COSE_Key 'alg'. Array position '3' */
    public static final long COSE_KEY_ALG = 3;

    /** COSE_Key 'key_ops'. Array position '4' */
    public static final long COSE_KEY_KEY_OPS = 4;

    /** COSE_Key 'Base IV'. Array position '5' */
    public static final long COSE_KEY_BASE_IV = 5;

    /* COSE_Key "Table 21: Key Type Values" */

    /** COSE_Key type 'OKP' name */
    public static final String COSE_KEY_TYPE_OKP_NAME = "OKP";

    /** COSE_Key type 'OKP' value */
    public static final long COSE_KEY_TYPE_OKP_VALUE = 1;

    /** COSE_Key type 'EC2' name */
    public static final String COSE_KEY_TYPE_EC2_NAME = "EC2";

    /** COSE_Key type 'EC2' value */
    public static final long COSE_KEY_TYPE_EC2_VALUE = 2;

    /** COSE_Key type 'Symmetric' name */
    public static final String COSE_KEY_TYPE_RSA_NAME = "RSA";

    /** COSE_Key type 'Symmetric' value */
    public static final long COSE_KEY_TYPE_RSA_VALUE = 3;

    /* RFC 9053 "CBOR Object Signing and Encryption (COSE): Initial Algorithms". Type 1 */

    /** COSE_Key type 'OKP', EC identifier -- Taken from the "COSE Elliptic Curves" registry */
    public static final long COSE_KEY_TYPE_OKP_CRV = -1;

    /** COSE_Key type 'OKP', Public Key */
    public static final long COSE_KEY_TYPE_OKP_X = -2;

    /** COSE_Key type 'OKP', Private Key */
    public static final long COSE_KEY_TYPE_OKP_D = -4;

    /* RFC 9053 "CBOR Object Signing and Encryption (COSE): Initial Algorithms". Type 2 */

    /** COSE_Key type 'EC2', EC identifier -- Taken from the "COSE Elliptic Curves" registry */
    public static final long COSE_KEY_TYPE_EC2_CRV = -1;

    /** COSE_Key type 'EC2', x-coordinate */
    public static final long COSE_KEY_TYPE_EC2_X = -2;

    /** COSE_Key type 'EC2', y-coordinate */
    public static final long COSE_KEY_TYPE_EC2_Y = -3;

    /** COSE_Key type 'EC2', Private key */
    public static final long COSE_KEY_TYPE_EC2_D = -4;

    /* RFC 8230 "Using RSA Algorithms with CBOR Object Signing and Encryption (COSE) Messages". Type 3 */

    /** COSE_Key type 'RSA', the RSA modulus n */
    public static final long COSE_KEY_TYPE_RSA_N = -1;

    /** COSE_Key type 'RSA', the RSA public exponent e */
    public static final long COSE_KEY_TYPE_RSA_E = -2;

    /** COSE_Key type 'RSA', the RSA private exponent d */
    public static final long COSE_KEY_TYPE_RSA_D = -3;

    /** COSE_Key type 'RSA', the prime factor p of n */
    public static final long COSE_KEY_TYPE_RSA_P = -4;

    /** COSE_Key type 'RSA', the prime factor q of n */
    public static final long COSE_KEY_TYPE_RSA_Q = -5;

    /** COSE_Key type 'RSA', dP is d mod (p - 1) */
    public static final long COSE_KEY_TYPE_RSA_DP = -6;

    /** COSE_Key type 'RSA', dQ is d mod (q - 1) */
    public static final long COSE_KEY_TYPE_RSA_DQ = -7;

    /** COSE_Key type 'RSA', qInv is the CRT coefficient q^(-1) mod p */
    public static final long COSE_KEY_TYPE_RSA_QINV = -8;

    /** COSE_Key type 'RSA', other prime infos, an array */
    public static final long COSE_KEY_TYPE_RSA_OTHER = -9;

    /** COSE_Key type 'RSA', a prime factor r_i of n, where i >= 3 */
    public static final long COSE_KEY_TYPE_RSA_R_I = -10;

    /** COSE_Key type 'RSA', d_i = d mod (r_i - 1) */
    public static final long COSE_KEY_TYPE_RSA_D_I = -11;

    /** COSE_Key type 'RSA', the CRT coefficient t_i = (r_1 * r_2 * ... * r_(i-1))^(-1) mod r_i */
    public static final long COSE_KEY_TYPE_RSA_T_I = -12;

    /**
     * Singleton
     */
    private COSEConstants() {
        // empty
    }

}
