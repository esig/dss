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

import java.io.Serializable;

import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.Digest;

public class CertificateRef implements Serializable {

	private static final long serialVersionUID = -325165164194282066L;
	
	private Digest certDigest;
	private IssuerSerialInfo issuerInfo;
	private CertificateRefOrigin origin;
	
	private String dssId;

	public Digest getCertDigest() {
		return certDigest;
	}

	public void setCertDigest(Digest certDigest) {
		this.certDigest = certDigest;
	}

	public IssuerSerialInfo getIssuerInfo() {
		return issuerInfo;
	}

	public void setIssuerInfo(IssuerSerialInfo issuerInfo) {
		this.issuerInfo = issuerInfo;
	}
	
	public CertificateRefOrigin getOrigin() {
		return origin;
	}
	
	public void setOrigin(CertificateRefOrigin origin) {
		this.origin = origin;
	}
	
	/**
	 * Returns revocation reference {@link String} id
	 * @return {@link String} id
	 */
	public String getDSSIdAsString() {
		if (dssId == null) {
			dssId = "C-" + certDigest.getHexValue().toUpperCase();
		}
		return dssId;
	}

	@Override
	public String toString() {
		return "CertificateRef [certDigest=" + certDigest + ", issuerInfo=" + issuerInfo + ", origin=" + origin + "]";
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof CertificateRef)) {
			return false;
		}
		CertificateRef o = (CertificateRef) obj;
		if ((certDigest == null && o.getCertDigest() != null) || 
				(certDigest != null && !certDigest.equals(o.getCertDigest()))) {
			return false;
		}
		if ((issuerInfo == null && o.getIssuerInfo() != null) || 
				(issuerInfo != null && !issuerInfo.equals(o.getIssuerInfo()))) {
			return false;
		}
		if ((origin == null && o.getOrigin() != null) || 
				(origin != null && !origin.equals(o.getOrigin()))) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((certDigest == null) ? 0 : certDigest.hashCode());
		result = (prime * result) + ((issuerInfo == null) ? 0 : issuerInfo.hashCode());
		result = (prime * result) + ((origin == null) ? 0 : origin.hashCode());
		return result;
	}

}
