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

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

/**
 * Represents a certificate reference wrapper
 *
 */
public class CertificateRefWrapper {
	
	/** The wrapped {@code XmlCertificateRef} */
	private final XmlCertificateRef certificateRef;

	/** The Id of the related certificate token */
	private final String certificateId;
	
	/**
	 * Default constructor
	 *
	 * @param certificateRef {@link XmlCertificateRef}
	 * @param certificateId {@link String} Id of the related certificate
	 */
	public CertificateRefWrapper(final XmlCertificateRef certificateRef, final String certificateId) {
		this.certificateRef = certificateRef;
		this.certificateId = certificateId;
	}
	
	/**
	 * Returns a certificate reference origin
	 * 
	 * @return {@link CertificateRefOrigin}
	 */
	public CertificateRefOrigin getOrigin() {
		return certificateRef.getOrigin();
	}
	
	/**
	 * Returns IssuerSerial's binaries
	 * 
	 * @return a byte array
	 */
	public byte[] getIssuerSerial() {
		if (certificateRef.getIssuerSerial() != null) {
			return certificateRef.getIssuerSerial().getValue();
		}
		return null;
	}
	
	/**
	 * Returns of IssuerSerial is present within the certificate reference
	 *
	 * @return TRUE if IssuerSerial is present, FALSE otherwise
	 */
	public boolean isIssuerSerialPresent() {
		return certificateRef.getIssuerSerial() != null;
	}
	
	/**
	 * Returns of IssuerSerial match with a found certificate
	 *
	 * @return TRUE if IssuerSerial matches with a found certificate , FALSE otherwise
	 */
	public boolean isIssuerSerialMatch() {
		if (certificateRef.getIssuerSerial() != null && certificateRef.getIssuerSerial().isMatch() != null) {
			return certificateRef.getIssuerSerial().isMatch();
		}
		return false;
	}

	/**
	 * Returns IssuerName
	 * 
	 * @return {@link String}
	 */
	public String getIssuerName() {
		if (certificateRef.getSerialInfo() != null) {
			return certificateRef.getSerialInfo().getIssuerName();
		}
		return null;
	}
	
	/**
	 * Returns SKI of the certificate
	 * (SHA-1 of the certificate's public key)
	 * 
	 * @return a byte array
	 */
	public byte[] getSki() {
		if (certificateRef.getSerialInfo() != null) {
			return certificateRef.getSerialInfo().getSki();
		}
		return null;
	}
	
	/**
	 * Returns digest algo and value
	 * 
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return certificateRef.getDigestAlgoAndValue();
	}

	/**
	 * Checks if the DigestAlgoAndValue of the reference present in the certificate reference
	 * 
	 * @return TRUE if DigestAlgoAndValue present in the certificate reference, FALSE otherwise
	 */
	public boolean isDigestValuePresent() {
		return getDigestAlgoAndValue() != null;
	}

	/**
	 * Returns a used {@code DigestAlgorithm} for a certificate reference creation
	 *
	 * @return {@link DigestAlgorithm}
	 */
	public DigestAlgorithm getDigestMethod() {
		XmlDigestAlgoAndValue digestAlgoAndValue = getDigestAlgoAndValue();
		if (digestAlgoAndValue != null) {
			return digestAlgoAndValue.getDigestMethod();
		}
		return null;
	}
	
	/**
	 * Checks if the DigestAlgoAndValue of the reference matches one of the certificate
	 * 
	 * @return TRUE if DigestAlgoAndValue matches the certificate, FALSE otherwise
	 */
	public boolean isDigestValueMatch() {
		XmlDigestAlgoAndValue digestAlgoAndValue = getDigestAlgoAndValue();
		return digestAlgoAndValue != null && digestAlgoAndValue.isMatch() != null && digestAlgoAndValue.isMatch();
	}

	/**
	 * Returns Id of the referenced certificate token (when available) or the reference id
	 *
	 * @return {@link String}
	 */
	public String getCertificateId() {
		return certificateId;
	}
	
	@Override
	public String toString() {
		if (certificateRef != null) {
			return "CertificateRefWrapper Origin='" + certificateRef.getOrigin() + "'";
		} else {
			return "CertificateRefWrapper certificateRef=" + certificateRef;
		}
	}

}
