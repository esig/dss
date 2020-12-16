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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Utils to retrieve public key size
 */
public final class DSSPKUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSPKUtils.class);

	private DSSPKUtils() {
	}

	/**
	 * This method returns a key length used to sign this token.
	 *
	 * @param token
	 *            {@link Token} (certificate, crl,...) to be checked
	 * @return the used key size to sign the given token
	 */
	public static String getPublicKeySize(Token token) {
		String keyLength = "?";
		PublicKey issuerPublicKey = null;
		if (token.getPublicKeyOfTheSigner() != null) {
			issuerPublicKey = token.getPublicKeyOfTheSigner();
		} else if (token.isSelfSigned()) {
			issuerPublicKey = ((CertificateToken) token).getPublicKey();
		}
		if (issuerPublicKey != null) {
			keyLength = String.valueOf(getPublicKeySize(issuerPublicKey));
		}
		return keyLength;
	}

	/**
	 * This method returns the public key size extracted from public key infrastructure.
	 *
	 * @param publicKey
	 *            {@link PublicKey}
	 * @return the key length
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
				publicKeySize = spec.getCurve().getField().getFieldSize();
			} else {
				publicKeySize = 0;
			}
		} else if (publicKey instanceof DSAPublicKey) {
			DSAPublicKey dsaPublicKey = (DSAPublicKey) publicKey;
			publicKeySize = dsaPublicKey.getParams().getP().bitLength();
		} else if (publicKey instanceof EdDSAPublicKey) {
			EdDSAPublicKey eddsaPK = (EdDSAPublicKey) publicKey;
			// remove prefix size
//			int prefixSize = Utils.fromHex("302a300506032b6570032100").length;
			int prefixSize = Utils.fromHex("3043300506032b6571033a00").length;
			return eddsaPK.getEncoded().length - prefixSize ;
		} else if (publicKey instanceof XDHPublicKey) {
			XDHPublicKey xdhPK = (XDHPublicKey) publicKey;
//			int prefixSize = Utils.fromHex("302a300506032b656e032100").length;
			int prefixSize = Utils.fromHex("3042300506032b656f033900").length;
			return xdhPK.getEncoded().length - prefixSize;
		} else {
			LOG.error("Unknown public key infrastructure: {}", publicKey.getClass().getName());
		}
		return publicKeySize;
	}

}
