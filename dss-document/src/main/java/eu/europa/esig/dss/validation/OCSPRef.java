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

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;

/**
 * Reference an OCSPResponse
 *
 *
 */

public class OCSPRef {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPRef.class);

	private DigestAlgorithm digestAlgorithm = null;

	private byte[] digestValue = DSSUtils.EMPTY_BYTE_ARRAY;

	private final boolean matchOnlyBasicOCSPResponse;

	/**
	 * The default constructor for OCSPRef.
	 */
	public OCSPRef(final OtherHash otherHash, final boolean matchOnlyBasicOCSPResponse) {

		if (otherHash != null) { // -444

			this.digestAlgorithm = DigestAlgorithm.forOID(otherHash.getHashAlgorithm().getAlgorithm());
			this.digestValue = otherHash.getHashValue();
		}
		this.matchOnlyBasicOCSPResponse = matchOnlyBasicOCSPResponse;
	}

	/**
	 * The default constructor for OCSPRef.
	 */
	public OCSPRef(DigestAlgorithm algorithm, byte[] digestValue, boolean matchOnlyBasicOCSPResponse) {

		this.digestAlgorithm = algorithm;
		this.digestValue = digestValue;
		this.matchOnlyBasicOCSPResponse = matchOnlyBasicOCSPResponse;
	}

	/**
	 * @param ocspResp
	 * @return
	 */
	public boolean match(final BasicOCSPResp ocspResp) {

		if (digestAlgorithm == null) { // -444
			return false;
		}
		try {

			MessageDigest digest = DSSUtils.getMessageDigest(digestAlgorithm);
			if (matchOnlyBasicOCSPResponse) {
				digest.update(ocspResp.getEncoded());
			} else {
				digest.update(DSSRevocationUtils.fromBasicToResp(ocspResp).getEncoded());
			}
			byte[] computedValue = digest.digest();
			if (LOG.isInfoEnabled()) {
				LOG.info("Compare " + Hex.encodeHexString(digestValue) + " to computed value " + Hex.encodeHexString(computedValue) + " of " +
					  "BasicOCSPResp produced at " + ocspResp.getProducedAt());
			}
			return Arrays.equals(digestValue, computedValue);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public byte[] getDigestValue() {
		return digestValue;
	}
}
