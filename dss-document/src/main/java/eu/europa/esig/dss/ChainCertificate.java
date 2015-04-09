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
package eu.europa.esig.dss;

import java.io.Serializable;

import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class represent an element of the certificate chain. Each element is composed of a {@code X509Certificate} and a {@code boolean} value idicating if the certificate must be
 * part of the signing certificate signed attribute.
 */
public class ChainCertificate implements Serializable {

	private CertificateToken x509Certificate;
	private boolean signedAttribute;

	/**
	 * This is the default constructor.
	 *
	 * @param x509Certificate encapsulated {@code X509Certificate}
	 */
	public ChainCertificate(final CertificateToken x509Certificate) {

		if (x509Certificate == null) {
			throw new NullPointerException("x509certificate");
		}
		this.x509Certificate = x509Certificate;
	}

	/**
	 * This is the full constructor associating the {@code X509Certificate} and the information indicating if the certificate must be added to the signing certificate signed
	 * attribute.
	 *
	 * @param x509Certificate encapsulated {@code X509Certificate}
	 * @param signedAttribute indicated if the certificate must be part of the signing certificate signed attribute
	 */
	public ChainCertificate(final CertificateToken x509Certificate, final boolean signedAttribute) {

		this(x509Certificate);
		this.signedAttribute = signedAttribute;
	}

	public CertificateToken getX509Certificate() {
		return x509Certificate;
	}

	public void setX509Certificate(final CertificateToken x509Certificate) {
		this.x509Certificate = x509Certificate;
	}

	public boolean isSignedAttribute() {
		return signedAttribute;
	}

	public void setSignedAttribute(final boolean signedAttribute) {
		this.signedAttribute = signedAttribute;
	}

	@Override
	public boolean equals(final Object o) {

		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		final ChainCertificate that = (ChainCertificate) o;
		if (!x509Certificate.equals(that.x509Certificate)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return x509Certificate.hashCode();
	}
}
