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
package eu.europa.esig.dss.attestation.common.key;

import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCXDHPublicKey;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * Default implementation of {@link PublicKeyInfoFactory}.
 * <p>
 * This implementation extracts key parameters from commonly used JCA and
 * Bouncy Castle public key implementations and converts them into a
 * provider-independent {@link PublicKeyInfo} representation.
 * <p>
 * The following key types are supported:
 * - ECDSA public keys represented by {@link ECPublicKey};
 * - EdDSA public keys represented by {@link BCEdDSAPublicKey};
 * - XDH public keys represented by {@link BCXDHPublicKey};
 * - RSA public keys represented by {@link RSAPublicKey}.
 * <p>
 * Applications using different cryptographic providers or custom public key
 * implementations may extend this class or provide a custom
 * {@link PublicKeyInfoFactory} implementation.
 *
 */
public class DefaultPublicKeyInfoFactory implements PublicKeyInfoFactory {

    static {
        Security.addProvider(DSSSecurityProvider.getSecurityProvider());
    }

    /**
     * Default constructor
     */
    public DefaultPublicKeyInfoFactory() {
        // empty
    }

    @Override
    public PublicKeyInfo create(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "Public key cannot be null!");

        if (publicKey instanceof ECPublicKey) {
            return createEC((ECPublicKey) publicKey);
        } else if (publicKey instanceof BCEdDSAPublicKey) {
            return createEdDSA((BCEdDSAPublicKey) publicKey);
        } else if (publicKey instanceof BCXDHPublicKey) {
            return createXDH((BCXDHPublicKey) publicKey);
        } else if (publicKey instanceof RSAPublicKey) {
            return createRSA((RSAPublicKey) publicKey);
        } else {
            throw new UnsupportedOperationException(String.format("The key of type '%s' is not supported! " +
                    "Provide a custom PublicKeyInfoFactory should you need to support the key.", publicKey.getClass().getSimpleName()));
        }
    }

    /**
     * Creates an EC public key representation.
     *
     * @param publicKey {@link ECPublicKey}
     * @return {@link PublicKeyInfo}
     */
    protected PublicKeyInfo createEC(ECPublicKey publicKey) {
        EllipticCurve curve = EllipticCurve.forParameter(publicKey.getParams());
        if (curve == null) {
            throw new UnsupportedOperationException("Unknown EC curve");
        }

        return PublicKeyInfo.ecKey(curve,
                toECUnsignedBytes(publicKey.getW().getAffineX(), curve.getSize()),
                toECUnsignedBytes(publicKey.getW().getAffineY(), curve.getSize()));
    }

    /**
     * Creates an EdDSA public key representation.
     *
     * @param publicKey {@link BCEdDSAPublicKey}
     * @return {@link PublicKeyInfo}
     */
    protected PublicKeyInfo createEdDSA(BCEdDSAPublicKey publicKey) {
        EllipticCurve curve = EllipticCurve.forLabel(publicKey.getAlgorithm());
        if (curve == null) {
            throw new UnsupportedOperationException(
                    "Unknown curve: " + publicKey.getAlgorithm());
        }

        return PublicKeyInfo.okpKey(
                curve,
                publicKey.getPointEncoding());
    }

    /**
     * Creates an XDH public key representation.
     *
     * @param publicKey {@link BCXDHPublicKey}
     * @return {@link PublicKeyInfo}
     */
    protected PublicKeyInfo createXDH(BCXDHPublicKey publicKey) {
        EllipticCurve curve = EllipticCurve.forLabel(publicKey.getAlgorithm());
        if (curve == null) {
            throw new UnsupportedOperationException(
                    "Unknown curve: " + publicKey.getAlgorithm());
        }

        return PublicKeyInfo.okpKey(
                curve,
                publicKey.getUEncoding());
    }

    /**
     * Creates an RSA public key representation.
     *
     * @param publicKey {@link RSAPublicKey}
     * @return {@link PublicKeyInfo}
     */
    protected PublicKeyInfo createRSA(RSAPublicKey publicKey) {

        return PublicKeyInfo.rsaKey(
                toRSAUnsignedBytes(publicKey.getModulus()),
                toRSAUnsignedBytes(publicKey.getPublicExponent()));
    }

    private byte[] toECUnsignedBytes(BigInteger bigInteger, int size) {
        byte[] bytes = bigInteger.toByteArray();

        if (bytes.length == size) {
            return bytes;
        }

        if (bytes.length == size + 1 && bytes[0] == 0x00) {
            return Utils.subarray(bytes, 1, bytes.length);
        }

        byte[] result = new byte[size];
        System.arraycopy(bytes, 0, result, size - bytes.length, bytes.length);

        return result;
    }

    private byte[] toRSAUnsignedBytes(BigInteger bigInteger) {
        byte[] bytes = bigInteger.toByteArray();

        if (bytes.length > 1 && bytes[0] == 0x00) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        return bytes;
    }

}