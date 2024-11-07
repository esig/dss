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
	 * The SigPolDocLocalURI shall have as value the URI referencing a local store
	 * where the present document can be retrieved.
	 */
	private String sigPolDocLocalURI;

	/**
	 * Default constructor instantiating object with null values
	 */
	public SignaturePolicyStore() {
		// empty
	}

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
	 * NOTE: one of signaturePolicyContent or sigPolDocLocalURI shall be used
	 * 
	 * @param signaturePolicyContent {@link DSSDocument}
	 */
	public void setSignaturePolicyContent(DSSDocument signaturePolicyContent) {
		this.signaturePolicyContent = signaturePolicyContent;
	}

	/**
	 * Gets SigPolDocLocalURI element value
	 *
	 * @return {@link String}
	 */
	public String getSigPolDocLocalURI() {
		return sigPolDocLocalURI;
	}

	/**
	 * Sets SigPolDocLocalURI element value, defining the local URI where the policy document can be retrieved
	 *
	 * NOTE: one of signaturePolicyContent or sigPolDocLocalURI shall be used
	 *
	 * @param sigPolDocLocalURI {@link String}
	 */
	public void setSigPolDocLocalURI(String sigPolDocLocalURI) {
		this.sigPolDocLocalURI = sigPolDocLocalURI;
	}

}
