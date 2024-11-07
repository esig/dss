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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;

import java.util.Date;
import java.util.List;

/**
 * Represents a revocation data wrapper
 *
 */
public class RevocationRefWrapper {

	/** The wrapped XML Revocation Ref */
	private final XmlRevocationRef revocationRef;

	/** The Id of the related revocation token */
	private final String revocationId;

	/**
	 * Default constructor
	 *
	 * @param revocationRef {@link XmlRevocationRef}
	 * @param revocationId {@link String} Id of the related revocation token
	 */
	public RevocationRefWrapper(final XmlRevocationRef revocationRef, final String revocationId) {
		this.revocationRef = revocationRef;
		this.revocationId = revocationId;
	}
	
	/**
	 * Returns a list of revocation reference origins
	 * 
	 * @return a list of {@link RevocationRefOrigin}s
	 */
	public List<RevocationRefOrigin> getOrigins() {
		return revocationRef.getOrigins();
	}

	/**
	 * Returns revocation ref production time if present
	 * 
	 * @return {@link Date}
	 */
	public Date getProductionTime() {
		return revocationRef.getProducedAt();
	}
	
	/**
	 * Returns responder's ID name if present
	 * 
	 * @return {@link String}
	 */
	public String getResponderIdName() {
		if (revocationRef.getResponderId() != null) {
			return revocationRef.getResponderId().getIssuerName();
		}
		return null;
	}
	
	/**
	 * Returns responder's ID key if present
	 * 
	 * @return a byte array
	 */
	public byte[] getResponderIdKey() {
		if (revocationRef.getResponderId() != null) {
			return revocationRef.getResponderId().getSki();
		}
		return null;
	}
	
	/**
	 * Returns digest algo and value
	 * 
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return revocationRef.getDigestAlgoAndValue();
	}
	
	/**
	 * Returns an Id of the related revocation token, when present. Returns Id of the reference otherwise.
	 *
	 * @return {@link String}
	 */
	public String getRevocationId() {
		return revocationId;
	}

	@Override
	public String toString() {
		if (revocationRef != null) {
			return "RevocationRefWrapper Origins='" + revocationRef.getOrigins().toArray() + "',  ProductionTime='" + revocationRef.getProducedAt() + 
					"', responderIdName='" + revocationRef.getResponderId().getIssuerName() + "'";
		} else {
			return "RevocationRefWrapper revocationRef=" + revocationRef;
		}
	}

}
