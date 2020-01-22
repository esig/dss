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
package eu.europa.esig.dss.ws.dto;

import java.util.List;

import eu.europa.esig.dss.enumerations.TimestampType;

public class TimestampDTO {

	private byte[] binaries;
	private String canonicalizationMethod;
	private TimestampType type;
	private List<TimestampIncludeDTO> includes;
	
	public TimestampDTO() {
	}
	
	public TimestampDTO(final byte[] binaries, final TimestampType type) {
		this.binaries = binaries;
		this.type = type;
	}

	public byte[] getBinaries() {
		return binaries;
	}
	
	public void setBinaries(byte[] binaries) {
		this.binaries = binaries;
	}

	public String getCanonicalizationMethod() {
		return canonicalizationMethod;
	}

	public void setCanonicalizationMethod(String canonicalizationMethod) {
		this.canonicalizationMethod = canonicalizationMethod;
	}

	public TimestampType getType() {
		return type;
	}
	
	public void setType(TimestampType type) {
		this.type = type;
	}
	
	public List<TimestampIncludeDTO> getIncludes() {
		return includes;
	}
	
	public void setIncludes(List<TimestampIncludeDTO> includes) {
		this.includes = includes;
	}
	
}
