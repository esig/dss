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
package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;

import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.utils.Utils;

/**
 * Reference an OCSPResponse
 */
public class OCSPRef extends RevocationRef {
	
	private static final long serialVersionUID = -4757221403735075782L;

	private static final Logger LOG = LoggerFactory.getLogger(OCSPRef.class);
	
	private Date producedAt = null;
	private ResponderId responderId = null;

	/**
	 * The default constructor for OCSPRef.
	 */
	public OCSPRef(Digest digest, Date producedAt, ResponderId responderId, RevocationRefOrigin origin) {
		this.digest = digest;
		this.producedAt = producedAt;
		this.responderId = responderId;
		this.origins = new HashSet<>(Arrays.asList(origin));
	}

	/**
	 * The default constructor for OCSPRef.
	 */
	public OCSPRef(final OcspResponsesID ocspResponsesID, RevocationRefOrigin origin) {
		final OtherHash otherHash = ocspResponsesID.getOcspRepHash();
		if (otherHash != null) {
			DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(otherHash.getHashAlgorithm().getAlgorithm().getId());
			byte[] digestValue = otherHash.getHashValue();
			this.digest = new Digest(digestAlgorithm, digestValue);
		} else {
			LOG.warn("Digest is not present for an OCSPRef with location [{}]!", origin.name());
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
		this.origins = new HashSet<>(Arrays.asList(origin));
	}
	
	public Date getProducedAt() {
		return producedAt;
	}
	
	public ResponderId getResponderId() {
		return responderId;
	}
	
	@Override
	public String getDSSIdAsString() {
		if (digest != null) {
			return super.getDSSIdAsString();
		}
		byte[] bytes;
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
			if (producedAt != null) {
				dos.writeLong(producedAt.getTime());
			}
			if (responderId.getKey() != null) {
				dos.write(responderId.getKey());
			}
			if (responderId.getName() != null) {
				dos.writeChars(responderId.getName());
			}
			dos.flush();
			bytes = baos.toByteArray();
		} catch (IOException e) {
			throw new DSSException("Cannot build DSS ID for the OCSP Ref.", e);
		}
		return "R-" + DSSUtils.toHex(DSSUtils.digest(DigestAlgorithm.SHA256, bytes)).toUpperCase();
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
				digest != null && !digest.equals(o.getDigest())) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((digest == null) ? 0 : digest.hashCode());
		result = prime * result + ((producedAt == null) ? 0 : producedAt.hashCode());
		result = prime * result + ((responderId.getName() == null) ? 0 : responderId.getName().hashCode());
		result = prime * result + ((responderId.getKey() == null) ? 0 : Arrays.hashCode(responderId.getKey()));
		return result;
	}
	
}
