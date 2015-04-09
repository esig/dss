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
package eu.europa.esig.dss.ws;

import java.util.Arrays;

/**
 *
 *
 *
 *
 *
 */
public class WSChainCertificate {

	private byte[] x509Certificate;
	private boolean signedAttribute;

	/**
	 * The default constructor
	 */
	public WSChainCertificate() {
	}

	public byte[] getX509Certificate() {
		return x509Certificate;
	}

	public void setX509Certificate(byte[] x509Certificate) {
		this.x509Certificate = x509Certificate;
	}

	public boolean isSignedAttribute() {
		return signedAttribute;
	}

	public void setSignedAttribute(boolean signedAttribute) {
		this.signedAttribute = signedAttribute;
	}

	@Override
	public String toString() {
		return "WSChainCertificate{" +
			  "x509Certificate=" + Arrays.toString(x509Certificate) +
			  ", signedAttribute=" + signedAttribute +
			  '}';
	}
}
