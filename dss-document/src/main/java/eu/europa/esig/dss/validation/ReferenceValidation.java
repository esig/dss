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
package eu.europa.esig.dss.validation;

import java.io.Serializable;

import eu.europa.esig.dss.Digest;

/**
 * This class is used to store individual reference validations.
 * 
 * For XAdES, that means reference tag(s) validation
 * 
 * For CAdES, that means message-digest validation
 *
 */
public class ReferenceValidation implements Serializable {

	private static final long serialVersionUID = 1L;

	private DigestMatcherType type;

	/* The pointed reference is found */
	private boolean found;
	/* The pointed reference is intact */
	private boolean intact;
	/* The embed digest value */
	private Digest digest;

	/* For XAdES : reference name/id */
	private String name;

	public DigestMatcherType getType() {
		return type;
	}

	public void setType(DigestMatcherType type) {
		this.type = type;
	}

	public boolean isFound() {
		return found;
	}

	public void setFound(boolean found) {
		this.found = found;
	}

	public boolean isIntact() {
		return intact;
	}

	public void setIntact(boolean intact) {
		this.intact = intact;
	}

	public Digest getDigest() {
		return digest;
	}

	public void setDigest(Digest digest) {
		this.digest = digest;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}
