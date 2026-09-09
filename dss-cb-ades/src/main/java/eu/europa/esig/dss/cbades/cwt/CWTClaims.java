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
package eu.europa.esig.dss.cbades.cwt;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORValueFactory;

/**
 * Contains a list of claims registered within RFC 8392: CBOR Web Token (CWT)
 *
 */
public enum CWTClaims {

    /**
     * 3.1.1. iss (Issuer) Claim
     * The "iss" (issuer) claim has the same meaning and processing rules as
     * the "iss" claim defined in Section 4.1.1 of [RFC7519], except that
     * the value is a StringOrURI, as defined in Section 2 of this
     * specification. The Claim Key 1 is used to identify this claim.
     */
    ISS(1L),

    /**
     * 3.1.2. sub (Subject) Claim
     * The "sub" (subject) claim has the same meaning and processing rules
     * as the "sub" claim defined in Section 4.1.2 of [RFC7519], except that
     * the value is a StringOrURI, as defined in Section 2 of this
     * specification. The Claim Key 2 is used to identify this claim.
     */
    SUB(2L),

    /**
     * 3.1.3. aud (Audience) Claim
     * The "aud" (audience) claim has the same meaning and processing rules
     * as the "aud" claim defined in Section 4.1.3 of [RFC7519], except that
     * the value of the audience claim is a StringOrURI when it is not an
     * array or each of the audience array element values is a StringOrURI
     * when the audience claim value is an array. (StringOrURI is defined
     * in Section 2 of this specification.) The Claim Key 3 is used to
     * identify this claim.
     */
    AUD(3L),

    /**
     * 3.1.4. exp (Expiration Time) Claim
     * The "exp" (expiration time) claim has the same meaning and processing
     * rules as the "exp" claim defined in Section 4.1.4 of [RFC7519],
     * except that the value is a NumericDate, as defined in Section 2 of
     * this specification. The Claim Key 4 is used to identify this claim.
     */
    EXP(4L),

    /**
     * 3.1.5. nbf (Not Before) Claim
     * The "nbf" (not before) claim has the same meaning and processing
     * rules as the "nbf" claim defined in Section 4.1.5 of [RFC7519],
     * except that the value is a NumericDate, as defined in Section 2 of
     * this specification. The Claim Key 5 is used to identify this claim.
     */
    NBF(5L),

    /** 
     * 3.1.6. iat (Issued At) Claim
     * The "iat" (issued at) claim has the same meaning and processing rules
     * as the "iat" claim defined in Section 4.1.6 of [RFC7519], except that
     * the value is a NumericDate, as defined in Section 2 of this
     * specification. The Claim Key 6 is used to identify this claim.
     */
    IAT(6L),

    /**
     * 3.1.7.  cti (CWT ID) Claim
     * The "cti" (CWT ID) claim has the same meaning and processing rules as
     * the "jti" claim defined in Section 4.1.7 of [RFC7519], except that
     * the value is a byte string. The Claim Key 7 is used to identify this
     * claim.
     */
    CTI(7L);

    /** Long encoded key */
    private final CBORValue cborKey;

    /**
     * Default constructor
     *
     * @param longKey long key value
     */
    CWTClaims(final Long longKey) {
        this.cborKey = CBORValueFactory.toCBORValue(longKey);
    }

    /**
     * Gets a representation of the key in a form of a CBOR object
     *
     * @return {@link CBORValue}
     */
    public CBORValue cbor() {
        return cborKey;
    }

}
