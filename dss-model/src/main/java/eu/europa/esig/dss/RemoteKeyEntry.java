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

@SuppressWarnings("serial")
public class RemoteKeyEntry implements Serializable {

	private String alias;
	private EncryptionAlgorithm encryptionAlgo;
	private RemoteCertificate certificate;
	private RemoteCertificate[] certificateChain;

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public EncryptionAlgorithm getEncryptionAlgo() {
		return encryptionAlgo;
	}

	public void setEncryptionAlgo(EncryptionAlgorithm encryptionAlgo) {
		this.encryptionAlgo = encryptionAlgo;
	}

	public RemoteCertificate getCertificate() {
		return certificate;
	}

	public void setCertificate(RemoteCertificate certificate) {
		this.certificate = certificate;
	}

	public RemoteCertificate[] getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(RemoteCertificate[] certificateChain) {
		this.certificateChain = certificateChain;
	}

}
