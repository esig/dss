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
package eu.europa.esig.dss.validation.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 *
 */
@XmlAccessorType(XmlAccessType.NONE)
public class Cryptographic {

	@XmlElement(name = "AlgoExpirationDate")
	private AlgoExpirationDateList algoExpirationDateList;

	@XmlElement(name = "MainSignature")
	private CertificateAlgorithms MainSignature;

	@XmlElement(name = "SigningCertificate")
	private SigningCertificate signingCertificate;

	@XmlElement(name = "CACertificate")
	private CertificateAlgorithms caCertificate;

	@XmlElement(name = "TimestampCertificate")
	private CertificateAlgorithms timestampCertificate;

	@XmlElement(name = "OCSPCertificate")
	private CertificateAlgorithms ocspCertificate;

	@XmlElement(name = "CRLCertificate")
	private CertificateAlgorithms crlCertificate;

	public AlgoExpirationDateList getAlgoExpirationDateList() {
		return algoExpirationDateList;
	}

	public void setAlgoExpirationDateList(AlgoExpirationDateList algoExpirationDateList) {
		this.algoExpirationDateList = algoExpirationDateList;
	}

	public CertificateAlgorithms getMainSignature() {
		return MainSignature;
	}

	public void setMainSignature(CertificateAlgorithms MainSignature) {
		this.MainSignature = MainSignature;
	}

	public SigningCertificate getSigningCertificate() {
		return signingCertificate;
	}

	public void setSigningCertificate(SigningCertificate signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	public CertificateAlgorithms getCaCertificate() {
		return caCertificate;
	}

	public void setCaCertificate(CertificateAlgorithms caCertificate) {
		this.caCertificate = caCertificate;
	}

	public CertificateAlgorithms getTimestampCertificate() {
		return timestampCertificate;
	}

	public void setTimestampCertificate(CertificateAlgorithms timestampCertificate) {
		this.timestampCertificate = timestampCertificate;
	}

	public CertificateAlgorithms getOcspCertificate() {
		return ocspCertificate;
	}

	public void setOcspCertificate(CertificateAlgorithms ocspCertificate) {
		this.ocspCertificate = ocspCertificate;
	}

	public CertificateAlgorithms getCrlCertificate() {
		return crlCertificate;
	}

	public void setCrlCertificate(CertificateAlgorithms crlCertificate) {
		this.crlCertificate = crlCertificate;
	}

	@Override
	public String toString() {
		return "Cryptographic{" +
				"algoExpirationDateList=" + algoExpirationDateList +
				", MainSignature=" + MainSignature +
				", signingCertificate=" + signingCertificate +
				", caCertificate=" + caCertificate +
				", timestampCertificate=" + timestampCertificate +
				", ocspCertificate=" + ocspCertificate +
				", crlCertificate=" + crlCertificate +
				'}';
	}


}
