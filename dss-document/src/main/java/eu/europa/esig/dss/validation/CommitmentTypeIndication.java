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

import java.util.List;

/**
 * This class represents the commitment type indication identifiers extracted from the signature.
 *
 */
public class CommitmentTypeIndication {

	/** URI or OID identifier */
    private final String identifier;

    /** The description message */
    private String description;

    /** The list of document references */
    private List<String> documentReferences;

	/**
	 * The default constructor
	 *
	 * @param identifier {@link String} URI or OID
	 */
	public CommitmentTypeIndication(String identifier) {
    	this.identifier = identifier;
    }

	/**
	 * Gets the identifier
	 *
	 * @return {@link String} URI or OID
	 */
	public String getIdentifier() {
        return identifier;
    }

	/**
	 * Gets the description
	 *
	 * @return {@link String}
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Sets the description
	 *
	 * @param description {@link String}
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * Gets the document references
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getDocumentReferences() {
		return documentReferences;
	}

	/**
	 * Sets the document references
	 *
	 * @param documentReferences a list of {@link String}s
	 */
	public void setDocumentReferences(List<String> documentReferences) {
		this.documentReferences = documentReferences;
	}

}
