/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.parameter;

import java.io.Serializable;
import java.security.cert.X509Certificate;

import eu.europa.ec.markt.dss.exception.DSSNullException;

/**
 * This class represent an element of the certificate chain. Each element is composed of a {@code X509Certificate} and a {@code boolean} value idicating if the certificate must be
 * part of the signing certificate signed attribute.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ChainCertificate implements Serializable {

	private X509Certificate x509Certificate;
	private boolean signedAttribute;

	/**
	 * This is the default constructor.
	 *
	 * @param x509Certificate encapsulated {@code X509Certificate}
	 */
	public ChainCertificate(final X509Certificate x509Certificate) {

		if (x509Certificate == null) {
			throw new DSSNullException(X509Certificate.class);
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
	public ChainCertificate(final X509Certificate x509Certificate, final boolean signedAttribute) {

		this(x509Certificate);
		this.signedAttribute = signedAttribute;
	}

	public X509Certificate getX509Certificate() {
		return x509Certificate;
	}

	public void setX509Certificate(final X509Certificate x509Certificate) {
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
