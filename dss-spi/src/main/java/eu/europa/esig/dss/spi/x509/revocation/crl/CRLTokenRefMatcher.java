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
package eu.europa.esig.dss.spi.x509.revocation.crl;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.RevocationTokenRefMatcher;

import java.util.Arrays;

/**
 * This class is used to match a CRL with a reference
 *
 */
public class CRLTokenRefMatcher implements RevocationTokenRefMatcher<CRL> {

	/**
	 * Default constructor
	 */
	public CRLTokenRefMatcher() {
		// empty
	}

	@Override
	public boolean match(RevocationToken<CRL> token, RevocationRef<CRL> reference) {
		final CRLToken crlToken = (CRLToken) token;
		final CRLRef crlRef = (CRLRef) reference;

		if (crlRef.getDigest() != null) {
			return matchByDigest(crlToken, crlRef.getDigest());
		} else {
			throw new DSSException("Digest is mandatory for comparison");
		}
	}

	@Override
	public boolean match(EncapsulatedRevocationTokenIdentifier<CRL> identifier, RevocationRef<CRL> reference) {
		final CRLBinary crlBinary = (CRLBinary) identifier;
		final CRLRef crlRef = (CRLRef) reference;

		if (crlRef.getDigest() != null) {
			return matchByDigest(crlBinary, crlRef.getDigest());
		} else {
			throw new DSSException("Digest is mandatory for comparison");
		}
	}
	
	private boolean matchByDigest(RevocationToken<CRL> token, Digest digest) {
		return Arrays.equals(digest.getValue(), token.getDigest(digest.getAlgorithm()));
	}
	
	private boolean matchByDigest(EncapsulatedRevocationTokenIdentifier<CRL> identifier, Digest digest) {
		return Arrays.equals(digest.getValue(), identifier.getDigestValue(digest.getAlgorithm()));
	}

}
