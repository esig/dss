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
package eu.europa.esig.dss.model;

/**
 * Represents the SignaturePolicyStore
 */
public class SignaturePolicyStore {

	/**
	 * Optional ID
	 */
	private String id;
	
	/**
	 * The SPDocSpecification element shall identify the technical specification
	 * that defines the syntax used for producing the signature policy document.
	 */
	private SpDocSpecification spDocSpecification;

	/**
	 * The SignaturePolicyDocument element shall contain the base-64 encoded
	 * signature policy.
	 */
	private DSSDocument signaturePolicyContent;

	/**
	 * Get Id (optional)
	 * 
	 * @return {@link String}
	 */
	public String getId() {
		return id;
	}

	/**
	 * Set Id (optional)
	 * 
	 * @param id {@link String}
	 */
	public void setId(String id) {
		this.id = id;
	}
	
	/**
	 * Get {@code SpDocSpecification} content
	 * 
	 * @return {@link SpDocSpecification}
	 */
	public SpDocSpecification getSpDocSpecification() {
		return spDocSpecification;
	}

	/**
	 * Set {@code SpDocSpecification}
	 * 
	 * @param spDocSpecification {@link SpDocSpecification}
	 */
	public void setSpDocSpecification(SpDocSpecification spDocSpecification) {
		this.spDocSpecification = spDocSpecification;
	}

	/**
	 * Get policy store content
	 * 
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getSignaturePolicyContent() {
		return signaturePolicyContent;
	}

	/**
	 * Set policy store content
	 * 
	 * @param signaturePolicyContent {@link DSSDocument}
	 */
	public void setSignaturePolicyContent(DSSDocument signaturePolicyContent) {
		this.signaturePolicyContent = signaturePolicyContent;
	}

}
