/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss;

import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("restriction")
public final class DSSPKUtils {

    private static final Logger LOG = LoggerFactory.getLogger(DSSPKUtils.class);

    private DSSPKUtils() {
    }

    /**
     * This method returns the public algorithm extracted from public key infrastructure. (ex: RSA)
     *
     * @param publicKey
     * @return
     */
    public static String getPublicKeyEncryptionAlgo(final Key publicKey) {

        String publicKeyAlgorithm = "?";
        // (List of different public key implementations with instanceOf test removed)
        publicKeyAlgorithm = publicKey.getAlgorithm();
        if (!"?".equals(publicKeyAlgorithm)) {

            try {

                publicKeyAlgorithm = EncryptionAlgorithm.forName(publicKeyAlgorithm).getName();
            } catch (DSSException e) {

                LOG.error(e.getMessage());
            }
        }
        return publicKeyAlgorithm;
    }

    /**
     * This method returns the public key size extracted from public key infrastructure.
     *
     * @param publicKey
     * @return
     */
    public static int getPublicKeySize(final PublicKey publicKey) {

        int publicKeySize = -1;
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            publicKeySize = rsaPublicKey.getModulus().bitLength();
        } else if (publicKey instanceof JCEECPublicKey) {

            /**
             * The security of EC systems relies on the size of q, and the size of an EC key refers to the bit-length of
             * the subgroup size q.
             */
            final JCEECPublicKey jceecPublicKey = (JCEECPublicKey) publicKey;
            ECParameterSpec spec = jceecPublicKey.getParameters();
            if (spec != null) {

                publicKeySize = spec.getN().bitLength();
            } else {
                // We support the key, but we don't know the key length
                publicKeySize = 0;
                // publicKeySize = jceecPublicKey.getQ().getCurve().getFieldSize();
            }
        } else if (publicKey instanceof ECPublicKey) {

            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            java.security.spec.ECParameterSpec spec = ecPublicKey.getParams();
            if (spec != null) {

                // TODO: (Bob: 20130528) To be checked (need an example)
                publicKeySize = spec.getCurve().getField().getFieldSize();
            } else {

                publicKeySize = 0;
            }
        } else if (publicKey instanceof DSAPublicKey) {
            DSAPublicKey dsaPublicKey = (DSAPublicKey) publicKey;
            publicKeySize = dsaPublicKey.getParams().getP().bitLength();
        } else {

            LOG.error("Unknown public key infrastructure: " + publicKey.getClass().getName());
        }
        return publicKeySize;
    }
}
