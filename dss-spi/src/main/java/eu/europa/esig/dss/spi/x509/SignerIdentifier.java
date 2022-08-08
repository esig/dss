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

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;

import javax.security.auth.x500.X500Principal;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Represents an ASN.1 SignerId DTO
 *
 */
public class SignerIdentifier implements Serializable {

	private static final long serialVersionUID = 8539151269599455910L;

	/** The X500Principal name of the certificate issue */
	private X500Principal issuerName;

	/** The certificate's serial number */
	private BigInteger serialNumber;

	/**  SHA-1 hash of certificate's public key (used in OCSP response) */
	private byte[] ski;

	/** the used CertificateIdentifier for a signature/timestamp */
	private boolean current;

	/**
	 * Default constructor instantiating object with null values
	 */
	public SignerIdentifier() {
		// empty
	}

	/**
	 * Returns the name of the certificate issuer
	 *
	 * @return {@link X500Principal}
	 */
	public X500Principal getIssuerName() {
		return issuerName;
	}

	/**
	 * Sets the name of the certificate's issuer
	 *
	 * @param name {@link X500Principal}
	 */
	public void setIssuerName(X500Principal name) {
		this.issuerName = name;
	}

	/**
	 * Returns the serial number of the signer certificate
	 *
	 * @return {@link BigInteger}
	 */
	public BigInteger getSerialNumber() {
		return serialNumber;
	}

	/**
	 * Sets serial number of the signer certificate
	 *
	 * @param serialNumber {@link BigInteger}
	 */
	public void setSerialNumber(BigInteger serialNumber) {
		this.serialNumber = serialNumber;
	}

	/**
	 * Returns SHA-1 of the certificate's public key
	 *
	 * @return byte array representation of the SHA-1
	 */
	public byte[] getSki() {
		return ski;
	}

	/**
	 * Sets SHA-1 of the certificate's public key
	 *
	 * @param ski byte array
	 */
	public void setSki(byte[] ski) {
		this.ski = ski;
	}

	/**
	 * Indicates if the SignerIdentifier is related to the current signature
	 *
	 * @return TRUE if it is related to the current signature, FALSE otherwise
	 */
	public boolean isCurrent() {
		return current;
	}

	/**
	 * Sets if the SignerIdentifier is related to the current signature
	 *
	 * @param current if related to the current signature
	 */
	public void setCurrent(boolean current) {
		this.current = current;
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
		SignerIdentifier id = new SignerIdentifier();
		id.setIssuerName(certificateToken.getIssuerX500Principal());
		id.setSerialNumber(certificateToken.getSerialNumber());
		id.setSki(DSSASN1Utils.getSki(certificateToken));
		return isEquivalent(id);
	}

	/**
	 * Checks if the given {@code signerIdentifier} is equivalent
	 *
	 * @param signerIdentifier {@link SignerIdentifier} to compare
	 * @return TRUE if the given object is equivalent, FALSE otherwise
	 */
	public boolean isEquivalent(SignerIdentifier signerIdentifier) {
		if (issuerName != null && serialNumber != null) {
			if (!DSSASN1Utils.x500PrincipalAreEquals(issuerName, signerIdentifier.getIssuerName())) {
				return false;
			}
			if (!serialNumber.equals(signerIdentifier.getSerialNumber())) {
				return false;
			}
			return true;
		} else {
			return Arrays.equals(ski, signerIdentifier.getSki());
		}
	}

	/**
	 * Checks if the SignerIdentifier is empty or not
	 *
	 * NOTE: in some cases the SignerIdentifier can not contain any values
	 *
	 * @return TRUE if the {@code SignerIdentifier} is empty, FALSE otherwise
	 */
	public boolean isEmpty() {
		return issuerName == null && serialNumber == null && Utils.isArrayEmpty(ski);
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
		SignerIdentifier other = (SignerIdentifier) obj;
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
