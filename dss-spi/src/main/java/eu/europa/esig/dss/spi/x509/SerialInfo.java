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
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;

public class SerialInfo {

	private X500Principal issuerName;
	private BigInteger serialNumber;
	
	private byte[] ski; // SHA-1 hash of cert's public key (used in OCSP response)
	
    private boolean validated; // the framework validates only the first SignerInfo

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

	public byte[] getSki() {
		return ski;
	}

	public void setSki(byte[] ski) {
		this.ski = ski;
	}

	public boolean isValidated() {
		return validated;
	}

	public void setValidated(boolean validated) {
		this.validated = validated;
	}
	
	/**
	 * Returns DER-encoded IssuerSerial representation of the object.
	 * NOTE: the issuerName and SerialNumber must be defined! Returns null in the opposite case
	 * 
	 * @return a byte array of the encoded IssuerSerial
	 */
	public byte[] getIssuerSerialEncoded() {
		if (issuerName != null && serialNumber != null) {
	        final X500Name issuerX500Name = X500Name.getInstance(issuerName.getEncoded());
	        final GeneralName generalName = new GeneralName(issuerX500Name);
	        final GeneralNames generalNames = new GeneralNames(generalName);
	        IssuerSerial issuerSerial = new IssuerSerial(generalNames, serialNumber);
	        return DSSASN1Utils.getDEREncoded(issuerSerial);
		}
		return null;
	}
	
	/**
	 * Checks if the current SerialInfo is related to a provided CertificateToken
	 * 
	 * @param certificateToken {@link CertificateToken} to check
	 * @return TRUE if the certificateToken is related to the SerialInfo, FALSE otherwise
	 */
	public boolean isRelatedToCertificate(CertificateToken certificateToken) {
		if (issuerName != null && serialNumber != null) {
			if (!DSSASN1Utils.x500PrincipalAreEquals(certificateToken.getIssuerX500Principal(), issuerName)) {
				return false;
			}
			if (serialNumber != null) {
				return certificateToken.getSerialNumber().equals(serialNumber);
			}
			return true;
		} else {
			return DSSASN1Utils.isSkiEqual(ski, certificateToken);
		}
	}

	@Override
	public String toString() {
		if (issuerName != null || serialNumber != null) {
			return "IssuerSerialInfo [issuerName=" + issuerName + ", serialNumber=" + serialNumber + "]";
		} else {
			return "IssuerSerialInfo [ski=" + Utils.toBase64(ski) + "]";
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((issuerName == null) ? 0 : issuerName.hashCode());
		result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
		result = prime * result + Arrays.hashCode(ski);
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
		if (getClass() != obj.getClass()) {
			return false;
		}
		SerialInfo other = (SerialInfo) obj;
		if (issuerName == null) {
			if (other.issuerName != null) {
				return false;
			}
		} else if (!issuerName.equals(other.issuerName)) {
			return false;
		}
		if (serialNumber == null) {
			if (other.serialNumber != null) {
				return false;
			}
		} else if (!serialNumber.equals(other.serialNumber)) {
			return false;
		}
		if (!Arrays.equals(ski, other.ski)) {
			return false;
		}
		return true;
	}

}
