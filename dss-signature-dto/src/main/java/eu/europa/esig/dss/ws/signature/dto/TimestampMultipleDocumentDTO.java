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
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;

import java.util.List;

/**
 * Request DTO to timestamps a list of documents
 */
public class TimestampMultipleDocumentDTO extends AbstractTimestampDocumentDTO {

	/** List of documents to be timestamped */
	private List<RemoteDocument> toTimestampDocuments;

	/**
	 * Empty constructor
	 */
	public TimestampMultipleDocumentDTO() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param toTimestampDocuments a list of {@link RemoteDocument}s to timestamp
	 * @param timestampParameters {@link RemoteTimestampParameters}
	 */
	public TimestampMultipleDocumentDTO(List<RemoteDocument> toTimestampDocuments,
										RemoteTimestampParameters timestampParameters) {
		super(timestampParameters);
		this.setToTimestampDocuments(toTimestampDocuments);
	}

	/**
	 * Gets a list of documents to be timestamped
	 *
	 * @return a list of {@link RemoteDocument}s
	 */
	public List<RemoteDocument> getToTimestampDocuments() {
		return toTimestampDocuments;
	}

	/**
	 * Sets a list of documents to be timestamped
	 *
	 * @param toTimestampDocuments a list of {@link RemoteDocument}s
	 */
	public void setToTimestampDocuments(List<RemoteDocument> toTimestampDocuments) {
		this.toTimestampDocuments = toTimestampDocuments;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((timestampParameters == null) ? 0 : timestampParameters.hashCode());
		result = (prime * result) + ((toTimestampDocuments == null) ? 0 : toTimestampDocuments.hashCode());
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
		TimestampMultipleDocumentDTO other = (TimestampMultipleDocumentDTO) obj;
		if (timestampParameters == null) {
			if (other.timestampParameters != null) {
				return false;
			}
		} else if (!timestampParameters.equals(other.timestampParameters)) {
			return false;
		}
		if (toTimestampDocuments == null) {
			if (other.toTimestampDocuments != null) {
				return false;
			}
		} else if (!toTimestampDocuments.equals(other.toTimestampDocuments)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "TimestampMultipleDocumentDTO [toTimestampDocuments=" + toTimestampDocuments + ", parameters=" + timestampParameters + "]";
	}

}
