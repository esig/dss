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
package eu.europa.esig.dss.signature;

import java.io.Serializable;

import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.SignatureValue;

/**
 * This class is a DTO to transfer required objects to execute signDocument method
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects ny GET (url size limitation)
 */
@SuppressWarnings("serial")
public class SignDocumentDTO implements Serializable {

	private RemoteDocument toSignDocument;
	private RemoteSignatureParameters parameters;
	private SignatureValue signatureValue;

	public SignDocumentDTO() {
	}

	public SignDocumentDTO(RemoteDocument toSignDocument, RemoteSignatureParameters parameters, SignatureValue signatureValue) {
		this.toSignDocument = toSignDocument;
		this.parameters = parameters;
		this.signatureValue = signatureValue;
	}

	public RemoteDocument getToSignDocument() {
		return toSignDocument;
	}

	public void setToSignDocument(RemoteDocument toSignDocument) {
		this.toSignDocument = toSignDocument;
	}

	public RemoteSignatureParameters getParameters() {
		return parameters;
	}

	public void setParameters(RemoteSignatureParameters parameters) {
		this.parameters = parameters;
	}

	public SignatureValue getSignatureValue() {
		return signatureValue;
	}

	public void setSignatureValue(SignatureValue signatureValue) {
		this.signatureValue = signatureValue;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((parameters == null) ? 0 : parameters.hashCode());
		result = (prime * result) + ((signatureValue == null) ? 0 : signatureValue.hashCode());
		result = (prime * result) + ((toSignDocument == null) ? 0 : toSignDocument.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SignDocumentDTO other = (SignDocumentDTO) obj;
		if (parameters == null) {
			if (other.parameters != null) {
				return false;
			}
		} else if (!parameters.equals(other.parameters)) {
			return false;
		}
		if (signatureValue == null) {
			if (other.signatureValue != null) {
				return false;
			}
		} else if (!signatureValue.equals(other.signatureValue)) {
			return false;
		}
		if (toSignDocument == null) {
			if (other.toSignDocument != null) {
				return false;
			}
		} else if (!toSignDocument.equals(other.toSignDocument)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "SignDocumentDTO [toSignDocument=" + toSignDocument + ", parameters=" + parameters + ", signatureValue=" + signatureValue + "]";
	}

}
