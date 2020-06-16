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
package eu.europa.esig.dss.diagnostic;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;

/**
 * Represents a revocation data wrapper
 *
 */
public class RevocationRefWrappper {
	
	private final XmlRevocationRef revocationRef;
	
	public RevocationRefWrappper(final XmlRevocationRef revocationRef) {
		this.revocationRef = revocationRef;
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
	 * Returns responser's ID name if present
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
	 * Returns responser's ID key if present
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
