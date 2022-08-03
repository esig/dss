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
package eu.europa.esig.dss.crl;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRLEntry;
import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * The utils for dealing with CRLs
 */
public class CRLUtils {

	private CRLUtils() {
		// empty
	}

	/**
	 * The provided implementation of CRL utils
	 */
	private static ICRLUtils impl;

	static {
		ServiceLoader<ICRLUtils> loader = ServiceLoader.load(ICRLUtils.class);
		Iterator<ICRLUtils> iterator = loader.iterator();
		if (!iterator.hasNext()) {
			throw new ExceptionInInitializerError(
					"No implementation found for ICRLUtils in classpath, please choose between dss-crl-parser-stream or dss-crl-parser-x509crl");
		}
		impl = iterator.next();
	}

	/**
	 * Takes binaries and returns DER encoded {@code CRLBinary}
	 * 
	 * @param binaries byte array representing an encoded CRL
	 * @return DER encoded {@link CRLBinary}
	 */
	public static CRLBinary buildCRLBinary(final byte[] binaries) {
		return impl.buildCRLBinary(binaries);
	}

	/**
	 * This method verifies and creates: the signature of the CRL, the key usage of its signing certificate and the coherence
	 * between the subject names of the CRL signing certificate and the issuer name of the certificate for which the
	 * verification of the revocation data is carried out. A dedicated object based on {@code CRLValidity} is created
	 * and accordingly updated.
	 *
	 * @param crlBinary
	 *            {@code CRLBinary} of the CRL to be created (cannot be null)
	 * @param issuerToken
	 *            {@code CertificateToken} used to sign the {@code X509CRL} (cannot be null)
	 * @return {@code CRLValidity}
	 * @throws IOException
	 *             if an IO error occurred
	 */
	public static CRLValidity buildCRLValidity(final CRLBinary crlBinary, final CertificateToken issuerToken) throws IOException {
		return impl.buildCRLValidity(crlBinary, issuerToken);
	}

	/**
	 * This method verifies the revocation status for a given serial number
	 * 
	 * @param crlValidity
	 *            the CRL Validity
	 * @param serialNumber
	 *            the certificate serial number to search
	 * @return the X509CRLEntry with the revocation date, the reason, or null if the serial number is not found
	 */
	public static X509CRLEntry getRevocationInfo(CRLValidity crlValidity, BigInteger serialNumber) {
		return impl.getRevocationInfo(crlValidity, serialNumber);
	}

}
