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
package eu.europa.esig.dss.test.signature;

import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * Class used during test to represent the result returned by
 * an external signature process.
 */
public class ExternalSignatureResult {

	private byte[] signedData;
	private SignatureValue signatureValue;
	private CertificateToken signingCertificate;

	public byte[] getSignedData() {
		return signedData;
	}

	public void setSignedData(byte[] signedData) {
		this.signedData = signedData;
	}

	public CertificateToken getSigningCertificate() {
		return signingCertificate;
	}

	public void setSigningCertificate(CertificateToken signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	public SignatureValue getSignatureValue() {
		return signatureValue;
	}

	public void setSignatureValue(SignatureValue signatureValue) {
		this.signatureValue = signatureValue;
	}

}
