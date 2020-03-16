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
package eu.europa.esig.dss.spi.x509;

import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;

public class IssuerSerialInfo {

	private X500Principal issuerName;
	private BigInteger serialNumber;

	public X500Principal getIssuerName() {
		return issuerName;
	}

	public void setIssuerName(X500Principal name) {
		this.issuerName = name;
	}

	public BigInteger getSerialNumber() {
		return serialNumber;
	}

	public void setSerialNumber(BigInteger serialNumber) {
		this.serialNumber = serialNumber;
	}

	public boolean isRelatedTo(CertificateToken certificateToken) {
		return ((serialNumber == null || certificateToken.getSerialNumber().equals(serialNumber))
				&& DSSUtils.x500PrincipalAreEquals(certificateToken.getSubject().getPrincipal(), issuerName));
	}

	@Override
	public String toString() {
		return "IssuerSerialInfo [issuerName=" + issuerName + ", serialNumber=" + serialNumber + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((issuerName == null) ? 0 : issuerName.hashCode());
		result = (prime * result) + ((serialNumber == null) ? 0 : serialNumber.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof IssuerSerialInfo)) {
			return false;
		}
		IssuerSerialInfo other = (IssuerSerialInfo) obj;
		if ((issuerName == null && other.getIssuerName() != null) || 
				(issuerName != null && !issuerName.equals(other.getIssuerName()))) {
			return false;
		}
		if ((serialNumber == null && other.getSerialNumber() != null) || 
				(serialNumber != null && !serialNumber.equals(other.getSerialNumber()))) {
			return false;
		}
		return true;
	}

}
