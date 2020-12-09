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
package eu.europa.esig.dss.ws.signature.dto;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

import java.util.List;
import java.util.Objects;

/**
 * This class is a DTO to transfer required objects to execute signDocument method
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation)
 */
@SuppressWarnings("serial")
public class SignMultipleDocumentDTO extends AbstractSignDocumentDTO {

	/** List of documents to be signed */
	private List<RemoteDocument> toSignDocuments;

	/**
	 * Empty constructor
	 */
	public SignMultipleDocumentDTO() {
		super(null, null);
	}

	/**
	 * Default constructor
	 *
	 * @param toSignDocuments a list of {@link RemoteDocument}s tob e signed
	 * @param parameters {@link RemoteSignatureParameters}
	 * @param signatureValue {@link SignatureValueDTO}
	 */
	public SignMultipleDocumentDTO(List<RemoteDocument> toSignDocuments, RemoteSignatureParameters parameters,
								   SignatureValueDTO signatureValue) {
		super(parameters, signatureValue);
		this.toSignDocuments = toSignDocuments;
	}

	/**
	 * Gets a list of documents to be signed
	 *
	 * @return a list of {@link RemoteDocument}s
	 */
	public List<RemoteDocument> getToSignDocuments() {
		return toSignDocuments;
	}

	/**
	 * Sets a list of documents to be signed
	 *
	 * @param toSignDocuments a list of {@link RemoteDocument}s
	 */
	public void setToSignDocuments(List<RemoteDocument> toSignDocuments) {
		this.toSignDocuments = toSignDocuments;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((toSignDocuments == null) ? 0 : toSignDocuments.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SignMultipleDocumentDTO other = (SignMultipleDocumentDTO) obj;
		if (!Objects.equals(toSignDocuments, other.toSignDocuments)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "SignDocumentDTO [toSignDocument=" + toSignDocuments + ", parameters=" + getParameters() + ", signatureValue=" + getSignatureValue() + "]";
	}

}
