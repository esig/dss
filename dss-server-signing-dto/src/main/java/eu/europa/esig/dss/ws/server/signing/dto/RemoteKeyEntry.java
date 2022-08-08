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
package eu.europa.esig.dss.ws.server.signing.dto;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

import java.io.Serializable;

/**
 * The DTO representing a Key entry
 */
@SuppressWarnings("serial")
public class RemoteKeyEntry implements Serializable {

	/** The key alias */
	private String alias;

	/** The encryption algorithm */
	private EncryptionAlgorithm encryptionAlgo;

	/** The certificate token binaries */
	private RemoteCertificate certificate;

	/** The certificate token's chain */
	private RemoteCertificate[] certificateChain;

	/**
	 * Default constructor initializing object with null values
	 */
	public RemoteKeyEntry() {
	}

	/**
	 * Gets the alias
	 *
	 * @return {@link String}
	 */
	public String getAlias() {
		return alias;
	}

	/**
	 * Sets the alias
	 *
	 * @param alias {@link String}
	 */
	public void setAlias(String alias) {
		this.alias = alias;
	}

	/**
	 * Gets the encryption algorithm
	 *
	 * @return {@link EncryptionAlgorithm}
	 */
	public EncryptionAlgorithm getEncryptionAlgo() {
		return encryptionAlgo;
	}

	/**
	 * Sets the encryption algorithm
	 *
	 * @param encryptionAlgo {@link EncryptionAlgorithm}
	 */
	public void setEncryptionAlgo(EncryptionAlgorithm encryptionAlgo) {
		this.encryptionAlgo = encryptionAlgo;
	}

	/**
	 * Gets the certificate token
	 *
	 * @return {@link RemoteCertificate}
	 */
	public RemoteCertificate getCertificate() {
		return certificate;
	}

	/**
	 * Sets the certificate token
	 *
	 * @param certificate {@link RemoteCertificate}
	 */
	public void setCertificate(RemoteCertificate certificate) {
		this.certificate = certificate;
	}

	/**
	 * Gets the certificate token's chain
	 *
	 * @return an array if {@link RemoteCertificate}s
	 */
	public RemoteCertificate[] getCertificateChain() {
		return certificateChain;
	}

	/**
	 * Sets the certificate token's chain
	 *
	 * @param certificateChain an array if {@link RemoteCertificate}s
	 */
	public void setCertificateChain(RemoteCertificate[] certificateChain) {
		this.certificateChain = certificateChain;
	}

}
