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
package eu.europa.esig.dss.attestation.mdoc.key;

import eu.europa.esig.dss.cbades.COSEConstants;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.attestation.common.key.PublicKeyInfo;

import java.util.Objects;

/**
 * Builds a COSE_Key representation from a {@link PublicKeyInfo}.
 * <p>
 * The generated structure complies with RFC 9052 "CBOR Object Signing and
 * Encryption (COSE): Structures and Process", Section 7 "Key Objects".
 * <p>
 * This builder operates on a provider-independent {@link PublicKeyInfo}
 * representation and converts it into a COSE {@link CBORMap}.
 * Supported key types are:
 * - EC2 keys (ECDSA);
 * - OKP keys (EdDSA and XDH);
 * - RSA keys.
 *
 */
public class COSEKeyBuilder {

    /** Provider-independent public key information used to construct the COSE_Key representation */
    private final PublicKeyInfo publicKeyInfo;

    /**
     * Default constructor
     *
     * @param publicKeyInfo {@link PublicKeyInfo}
     */
    public COSEKeyBuilder(final PublicKeyInfo publicKeyInfo) {
        Objects.requireNonNull(publicKeyInfo, "Key info cannot be null");
        this.publicKeyInfo = publicKeyInfo;
    }

    /**
     * Builds the COSE_Key representation.
     * <p>
     * Depending on the type of {@link PublicKeyInfo}, the resulting COSE_Key
     * is encoded as:
     * - EC2 key;
     * - OKP key;
     * - RSA key.
     *
     * @return {@link CBORMap} the COSE_Key representation
     */
    public CBORMap create() {
        if (publicKeyInfo instanceof PublicKeyInfo.ECKey) {
            return createEC((PublicKeyInfo.ECKey) publicKeyInfo);
        } else if (publicKeyInfo instanceof PublicKeyInfo.OKPKey) {
            return createOKP((PublicKeyInfo.OKPKey) publicKeyInfo);
        } else if (publicKeyInfo instanceof PublicKeyInfo.RSAKey) {
            return createRSA((PublicKeyInfo.RSAKey) publicKeyInfo);
        }
        throw new UnsupportedOperationException(String.format(
                "Unsupported key info type: '%s'", publicKeyInfo.getClass().getSimpleName()));
    }

    private CBORMap createEC(PublicKeyInfo.ECKey publicKeyInfo) {
        final CBORMap map = new CBORMap();
        map.put(COSEConstants.COSE_KEY_KTY, COSEConstants.COSE_KEY_TYPE_EC2_VALUE);
        map.put(COSEConstants.COSE_KEY_TYPE_EC2_CRV, publicKeyInfo.getCurve().getCOSEValue());
        map.put(COSEConstants.COSE_KEY_TYPE_EC2_X, publicKeyInfo.getX());
        map.put(COSEConstants.COSE_KEY_TYPE_EC2_Y, publicKeyInfo.getY());
        return map;
    }

    private CBORMap createOKP(PublicKeyInfo.OKPKey publicKeyInfo) {
        final CBORMap map = new CBORMap();
        map.put(COSEConstants.COSE_KEY_KTY, COSEConstants.COSE_KEY_TYPE_OKP_VALUE);
        map.put(COSEConstants.COSE_KEY_TYPE_OKP_CRV, publicKeyInfo.getCurve().getCOSEValue());
        map.put(COSEConstants.COSE_KEY_TYPE_OKP_X, publicKeyInfo.getX());
        return map;
    }

    private CBORMap createRSA(PublicKeyInfo.RSAKey publicKeyInfo) {
        final CBORMap map = new CBORMap();
        map.put(COSEConstants.COSE_KEY_KTY, COSEConstants.COSE_KEY_TYPE_RSA_VALUE);
        map.put(COSEConstants.COSE_KEY_TYPE_RSA_N, publicKeyInfo.getModulus());
        map.put(COSEConstants.COSE_KEY_TYPE_RSA_E, publicKeyInfo.getExponent());
        return map;
    }

}