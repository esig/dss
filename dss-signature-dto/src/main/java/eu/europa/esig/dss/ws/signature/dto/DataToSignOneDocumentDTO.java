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

import java.util.Objects;

import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

/**
 * This class is a DTO to transfer required objects to execute getDataToSign method
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation)
 */
@SuppressWarnings("serial")
public class DataToSignOneDocumentDTO extends AbstractDataToSignDTO {

	private RemoteDocument toSignDocument;

	public DataToSignOneDocumentDTO() {
		super(null);
	}

	public DataToSignOneDocumentDTO(RemoteDocument toSignDocument, RemoteSignatureParameters parameters) {
		super(parameters);
		this.toSignDocument = toSignDocument;
	}

	public RemoteDocument getToSignDocument() {
		return toSignDocument;
	}

	public void setToSignDocument(RemoteDocument toSignDocument) {
		this.toSignDocument = toSignDocument;
	}

	@Override
	public String toString() {
		return "DataToSignDTO [toSignDocument=" + toSignDocument + ", parameters=" + getParameters() + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((toSignDocument == null) ? 0 : toSignDocument.hashCode());
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
		DataToSignOneDocumentDTO other = (DataToSignOneDocumentDTO) obj;
		if (!Objects.equals(toSignDocument, other.toSignDocument)) {
			return false;
		}
		return true;
	}

}
