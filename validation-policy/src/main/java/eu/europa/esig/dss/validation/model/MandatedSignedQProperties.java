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
public class MandatedSignedQProperties {

	@XmlElement(name = "SigningTime")
	private boolean signingTime = false;

	@XmlElement(name = "ContentHints")
	private boolean contentHints = false;

	@XmlElement(name = "ContentReference")
	private boolean contentReference = false;

	@XmlElement(name = "ContentIdentifier")
	private boolean contentIdentifier = false;

	@XmlElement(name = "CommitmentTypeIndication")
	private boolean commitmentTypeIndication = false;

	@XmlElement(name = "SignerLocation")
	private boolean signerLocation = false;

	@XmlElement(name = "SignerAttributes")
	private boolean signerAttributes = false;

	@XmlElement(name = "ContentTimeStamp")
	private boolean contentTimeStamp = false;

	public boolean isSigningTime() {
		return signingTime;
	}

	public void setSigningTime(boolean signingTime) {
		this.signingTime = signingTime;
	}

	public boolean isContentHints() {
		return contentHints;
	}

	public void setContentHints(boolean contentHints) {
		this.contentHints = contentHints;
	}

	public boolean isContentReference() {
		return contentReference;
	}

	public void setContentReference(boolean contentReference) {
		this.contentReference = contentReference;
	}

	public boolean isContentIdentifier() {
		return contentIdentifier;
	}

	public void setContentIdentifier(boolean contentIdentifier) {
		this.contentIdentifier = contentIdentifier;
	}

	public boolean isCommitmentTypeIndication() {
		return commitmentTypeIndication;
	}

	public void setCommitmentTypeIndication(boolean commitmentTypeIndication) {
		this.commitmentTypeIndication = commitmentTypeIndication;
	}

	public boolean isSignerLocation() {
		return signerLocation;
	}

	public void setSignerLocation(boolean signerLocation) {
		this.signerLocation = signerLocation;
	}

	public boolean isSignerAttributes() {
		return signerAttributes;
	}

	public void setSignerAttributes(boolean signerAttributes) {
		this.signerAttributes = signerAttributes;
	}

	public boolean isContentTimeStamp() {
		return contentTimeStamp;
	}

	public void setContentTimeStamp(boolean contentTimeStamp) {
		this.contentTimeStamp = contentTimeStamp;
	}

	@Override
	public String toString() {
		return "MandatedSignedQProperties{" +
				"signingTime=" + signingTime +
				", contentHints=" + contentHints +
				", contentReference=" + contentReference +
				", contentIdentifier=" + contentIdentifier +
				", commitmentTypeIndication=" + commitmentTypeIndication +
				", signerLocation=" + signerLocation +
				", signerAttributes=" + signerAttributes +
				", contentTimeStamp=" + contentTimeStamp +
				'}';
	}
}
