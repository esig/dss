/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.ws.signature.dto;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;

/**
 * This class is a DTO that contains a set of parameters needed for a single document timestamping
 * It's only possible to transfer an object by POST and REST.
 * It's impossible to transfer big objects by GET (url size limitation)
 */
public class TimestampOneDocumentDTO extends AbstractTimestampDocumentDTO {

	/** The document to be timestamped */
	private RemoteDocument toTimestampDocument;

	/**
	 * Empty constructor
	 */
	public TimestampOneDocumentDTO() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param toTimestampDocument {@link RemoteDocument} to be timestamped
	 * @param timestampParameters {@link RemoteTimestampParameters}
	 */
	public TimestampOneDocumentDTO(RemoteDocument toTimestampDocument, RemoteTimestampParameters timestampParameters) {
		super(timestampParameters);
		this.toTimestampDocument = toTimestampDocument;
	}

	/**
	 * Gets a document to be timestamped
	 *
	 * @return {@link RemoteDocument}
	 */
	public RemoteDocument getToTimestampDocument() {
		return toTimestampDocument;
	}

	/**
	 * Sets a document to be timestamped
	 *
	 * @param toTimestampDocument {@link RemoteDocument}
	 */
	public void setToTimestampDocument(RemoteDocument toTimestampDocument) {
		this.toTimestampDocument = toTimestampDocument;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((timestampParameters == null) ? 0 : timestampParameters.hashCode());
		result = (prime * result) + ((toTimestampDocument == null) ? 0 : toTimestampDocument.hashCode());
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
		TimestampOneDocumentDTO other = (TimestampOneDocumentDTO) obj;
		if (timestampParameters == null) {
			if (other.timestampParameters != null) {
				return false;
			}
		} else if (!timestampParameters.equals(other.timestampParameters)) {
			return false;
		}
		if (toTimestampDocument == null) {
			if (other.toTimestampDocument != null) {
				return false;
			}
		} else if (!toTimestampDocument.equals(other.toTimestampDocument)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "TimestampOneDocumentDTO [toTimestampDocument=" + toTimestampDocument + ", parameters=" + timestampParameters + "]";
	}

}
