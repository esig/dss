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
package eu.europa.esig.dss.spi.x509.tsp;

import eu.europa.esig.dss.enumerations.TimestampedObjectType;

import java.io.Serializable;

/**
 * This class stocks the timestamped reference, which is composed of: - the
 * timestamp reference category {@code TimestampReferenceCategory}; - object id
 * in the case where the reference apply to the signature.
 */
public class TimestampedReference implements Serializable {

	private static final long serialVersionUID = -6147592379027843583L;

	/** Id of the timestamped object */
	private final String objectId;

	/** Timestamped object type */
	private final TimestampedObjectType category;

	/**
	 * Default constructor
	 *
	 * @param objectId {@link String}
	 * @param category {@link TimestampedObjectType}
	 */
	public TimestampedReference(final String objectId, final TimestampedObjectType category) {
		this.objectId = objectId;
		this.category = category;
	}

	/**
	 * Gets the timestamped object type
	 *
	 * @return {@link TimestampedObjectType}
	 */
	public TimestampedObjectType getCategory() {
		return category;
	}

	/**
	 * Gets the timestamped object Id
	 *
	 * @return {@link String}
	 */
	public String getObjectId() {
		return objectId;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((category == null) ? 0 : category.hashCode());
		result = prime * result + ((objectId == null) ? 0 : objectId.hashCode());
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
		TimestampedReference other = (TimestampedReference) obj;
		if (category != other.category) {
			return false;
		}
		if (objectId == null) {
			if (other.objectId != null) {
				return false;
			}
		} else if (!objectId.equals(other.objectId)) {
			return false;
		}
		return true;
	}
	
	@Override
	public String toString() {
		return String.format("TimestampedReference with Id [%s] and type [%s]", getObjectId(), getCategory());
	}

}
