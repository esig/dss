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

import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("serial")
public class RemoteSignatureParameters extends AbstractSerializableSignatureParameters {

	private RemoteCertificate signingCertificate;
	private List<RemoteCertificate> certificateChain = new ArrayList<RemoteCertificate>();

	/**
	 * The documents to be signed
	 */
	private List<RemoteDocument> detachedContents;

	/**
	 * ASiC Container type
	 */
	private ASiCContainerType asicContainerType;

	public RemoteSignatureParameters() {
	}

	public RemoteCertificate getSigningCertificate() {
		return signingCertificate;
	}

	public void setSigningCertificate(RemoteCertificate signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	public List<RemoteCertificate> getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(List<RemoteCertificate> certificateChain) {
		this.certificateChain = certificateChain;
	}

	public List<RemoteDocument> getDetachedContents() {
		return detachedContents;
	}

	public void setDetachedContents(List<RemoteDocument> detachedContents) {
		this.detachedContents = detachedContents;
	}

	public ASiCContainerType getAsicContainerType() {
		return asicContainerType;
	}

	public void setAsicContainerType(ASiCContainerType asicContainerType) {
		this.asicContainerType = asicContainerType;
	}

}
