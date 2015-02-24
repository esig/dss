/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.ocsp;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSRevocationUtils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * Reference an OCSPResponse
 *
 * @version $Revision$ - $Date$
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
