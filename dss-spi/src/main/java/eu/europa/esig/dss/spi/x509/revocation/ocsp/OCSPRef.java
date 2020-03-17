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

import java.util.Date;

import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.ResponderId;
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
		super(digest, origin);
		this.producedAt = producedAt;
		this.responderId = responderId;
	}

	/**
	 * The default constructor for OCSPRef.
	 */
	public OCSPRef(final OcspResponsesID ocspResponsesID, RevocationRefOrigin origin) {
		super(extractDigest(ocspResponsesID), origin);
		this.producedAt = DSSASN1Utils.getDate(ocspResponsesID.getOcspIdentifier().getProducedAt());
		this.responderId = new ResponderId();
		X500Name name = ocspResponsesID.getOcspIdentifier().getOcspResponderID().getName();
		if (name != null) {
			this.responderId.setX500Principal(DSSASN1Utils.toX500Principal(name));
		}
		byte[] key = ocspResponsesID.getOcspIdentifier().getOcspResponderID().getKeyHash();
		if (Utils.isArrayNotEmpty(key)) {
			this.responderId.setSki(key);
		}
	}
	
	private static Digest extractDigest(final OcspResponsesID ocspResponsesID) {
		final OtherHash otherHash = ocspResponsesID.getOcspRepHash();
		if (otherHash != null) {
			DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(otherHash.getHashAlgorithm().getAlgorithm().getId());
			byte[] digestValue = otherHash.getHashValue();
			return new Digest(digestAlgorithm, digestValue);
		} else {
			LOG.warn("Digest is not present for an OCSPRef!");
			return null;
		}
	}
	
	public Date getProducedAt() {
		return producedAt;
	}
	
	public ResponderId getResponderId() {
		return responderId;
	}
	
	@Override
	protected Identifier createIdentifier() {
		return new OCSPRefIdentifier(this);
	}
	
	@Override
	public String toString() {
		if (responderId.getX500Principal() != null) {
			return "OCSP Reference produced at [" + DSSUtils.formatInternal(producedAt) + "] "
					+ "with Responder Name: [" + responderId.getX500Principal() + "]";
		} else {
			return "OCSP Reference produced at [" + DSSUtils.formatInternal(producedAt) + "] "
					+ "with Responder key 64base: [" + Utils.toBase64(responderId.getSki()) + "]";
		}
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		OCSPRef other = (OCSPRef) obj;
		if (producedAt == null) {
			if (other.producedAt != null) {
				return false;
			}
		} else if (!producedAt.equals(other.producedAt)) {
			return false;
		}
		if (responderId == null) {
			if (other.responderId != null) {
				return false;
			}
		} else if (!responderId.equals(other.responderId)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((producedAt == null) ? 0 : producedAt.hashCode());
		result = prime * result + ((responderId == null) ? 0 : responderId.hashCode());
		return result;
	}
	
}
