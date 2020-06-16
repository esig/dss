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

public class Status {

	private final String message;
	private final Collection<String> relatedObjectIds;

	public Status(String message) {
		this.message = message;
		this.relatedObjectIds = null;
	}

	public Status(String message, Collection<String> relatedObjectIds) {
		this.message = message;
		this.relatedObjectIds = relatedObjectIds;
	}

	public String getMessage() {
		return message;
	}

	public Collection<String> getRelatedObjectIds() {
		return relatedObjectIds;
	}

	public boolean isEmpty() {
		return message == null || message.isEmpty();
	}

	@Override
	public String toString() {
		return message + (relatedObjectIds == null ? "" : " " + relatedObjectIds);
	}

}
