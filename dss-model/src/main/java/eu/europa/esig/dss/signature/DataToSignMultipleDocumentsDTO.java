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
import java.util.List;

import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;

/**
 * This class is a DTO to transfer required objects to execute getDataToSign method
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation)
 */
@SuppressWarnings("serial")
public class DataToSignMultipleDocumentsDTO extends AbstractDataToSignDTO implements Serializable {

	private List<RemoteDocument> toSignDocuments;

	public DataToSignMultipleDocumentsDTO() {
		super(null);
	}

	public DataToSignMultipleDocumentsDTO(List<RemoteDocument> toSignDocuments, RemoteSignatureParameters parameters) {
		super(parameters);
		this.toSignDocuments = toSignDocuments;
	}

	public List<RemoteDocument> getToSignDocuments() {
		return toSignDocuments;
	}

	public void setToSignDocuments(List<RemoteDocument> toSignDocuments) {
		this.toSignDocuments = toSignDocuments;
	}

	@Override
	public String toString() {
		return "DataToSignDTO [toSignDocument=" + toSignDocuments + ", parameters=" + getParameters() + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((getParameters() == null) ? 0 : getParameters().hashCode());
		result = (prime * result) + ((toSignDocuments == null) ? 0 : toSignDocuments.hashCode());
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
		DataToSignMultipleDocumentsDTO other = (DataToSignMultipleDocumentsDTO) obj;
		if (getParameters() == null) {
			if (other.getParameters() != null) {
				return false;
			}
		} else if (!getParameters().equals(other.getParameters())) {
			return false;
		}
		if (toSignDocuments == null) {
			if (other.toSignDocuments != null) {
				return false;
			}
		} else if (!toSignDocuments.equals(other.toSignDocuments)) {
			return false;
		}
		return true;
	}

}
