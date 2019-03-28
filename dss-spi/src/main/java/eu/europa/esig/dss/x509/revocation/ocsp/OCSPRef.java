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
package eu.europa.esig.dss.x509.revocation.ocsp;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.revocation.RevocationRef;

/**
 * Reference an OCSPResponse
 */
public class OCSPRef extends RevocationRef {

	private static final Logger LOG = LoggerFactory.getLogger(OCSPRef.class);
	
	private Date producedAt = null;
	private ResponderId responderId = null;

	private final boolean matchOnlyBasicOCSPResponse;
	
	public OCSPRef(Date producedAt, ResponderId responderId, boolean matchOnlyBasicOCSPResponse) {
		this.producedAt = producedAt;
		this.responderId = responderId;
		this.matchOnlyBasicOCSPResponse = matchOnlyBasicOCSPResponse;
	}

	/**
	 * The default constructor for OCSPRef.
	 */
	public OCSPRef(DigestAlgorithm algorithm, byte[] digestValue, Date producedAt, ResponderId responderId, boolean matchOnlyBasicOCSPResponse) {
		this(producedAt, responderId, matchOnlyBasicOCSPResponse);
		this.digestAlgorithm = algorithm;
		this.digestValue = digestValue;
	}

	/**
	 * The default constructor for OCSPRef.
	 */
	public OCSPRef(final OcspResponsesID ocspResponsesID) {
		final OtherHash otherHash = ocspResponsesID.getOcspRepHash();
		if (otherHash != null) {
			this.digestAlgorithm = DigestAlgorithm.forOID(otherHash.getHashAlgorithm().getAlgorithm().getId());
			this.digestValue = otherHash.getHashValue();
		}
		
		this.producedAt = DSSASN1Utils.getDate(ocspResponsesID.getOcspIdentifier().getProducedAt());
		
		this.responderId = new ResponderId();
		X500Name name = ocspResponsesID.getOcspIdentifier().getOcspResponderID().getName();
		if (name != null) {
			this.responderId.setName(name.toString());
		}
		byte[] key = ocspResponsesID.getOcspIdentifier().getOcspResponderID().getKeyHash();
		if (Utils.isArrayNotEmpty(key)) {
			this.responderId.setKey(key);
		}
		
		this.matchOnlyBasicOCSPResponse = true;
	}

	/**
	 * @param ocspResp {@link BasicOCSPResp}
	 * @return TRUE if the {@code ocspResp} matches, FALSE otherwise
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
				LOG.info("Compare " + Utils.toHex(digestValue) + " to computed value " + Utils.toHex(computedValue) + " of " + "BasicOCSPResp produced at "
						+ ocspResp.getProducedAt());
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
	
	public Date getProducedAt() {
		return producedAt;
	}
	
	public ResponderId getResponderId() {
		return responderId;
	}
	
	@Override
	public String toString() {
		if (responderId.getName() != null) {
			return "OCSP Reference produced at [" + DSSUtils.formatInternal(producedAt) + "] "
					+ "with Responder Name: [" + responderId.getName() + "]";
		} else {
			return "OCSP Reference produced at [" + DSSUtils.formatInternal(producedAt) + "] "
					+ "with Responder key 64base: [" + Utils.toBase64(responderId.getKey()) + "]";
		}
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof OCSPRef)) {
			return false;
		}
		OCSPRef o = (OCSPRef) obj;
		if (!producedAt.equals(o.producedAt) || 
				responderId.getName() != null && !responderId.getName().equals(o.getResponderId().getName()) ||
				responderId.getKey() != null && !Arrays.equals(responderId.getKey(), o.getResponderId().getKey()) ||
				digestAlgorithm != null && !digestAlgorithm.equals(o.getDigestAlgorithm()) || 
				digestValue != null && !Arrays.equals(digestValue, o.getDigestValue())) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(producedAt, responderId.getName(), responderId.getKey(), digestAlgorithm, digestValue);
	}
	
}
