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
package eu.europa.esig.dss.alert.status;

import java.util.Collection;

/**
 * The class used for a custom event creation
 */
public class Status {

	/** Defines a message of the event */
	private final String message;

	/** Defines a collection of object ids associated with the event */
	private final Collection<String> relatedObjectIds;

	/**
	 * The constructor taking a message only as an input
	 *
	 * @param message {@link String} message describing the event
	 */
	public Status(String message) {
		this.message = message;
		this.relatedObjectIds = null;
	}

	/**
	 * The default constructor
	 *
	 * @param message {@link String} the message associated with the event
	 * @param relatedObjectIds a collection of {@link String} object ids, associated with the event
	 */
	public Status(String message, Collection<String> relatedObjectIds) {
		this.message = message;
		this.relatedObjectIds = relatedObjectIds;
	}

	/**
	 * Returns the message event
	 *
	 * @return {@link String}
	 */
	public String getMessage() {
		return message;
	}

	/**
	 * Returns a list of object ids associated with the event
	 *
	 * @return a collection of {@link String} object ids associated with the event
	 */
	public Collection<String> getRelatedObjectIds() {
		return relatedObjectIds;
	}

	/**
	 * Returns of the Status event is not filled (all values are null)
	 *
	 * @return TRUE if the Status is empty, FALSE otherwise
	 */
	public boolean isEmpty() {
		return message == null || message.isEmpty();
	}

	@Override
	public String toString() {
		return message + (relatedObjectIds == null ? "" : " " + relatedObjectIds);
	}

}
