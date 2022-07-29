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
package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.utils.Utils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A container with JWS signature attributes
 */
public class JWSJsonSerializationObject implements Serializable {

	private static final long serialVersionUID = -372703330907087721L;

	/** The JWS payload */
	private String payload;
	
	/** The list of incorporated signatures */
	private List<JWS> signatures;
	
	/** Defines the JWSSerializationType of the JAdES signature */
	private JWSSerializationType jwsSerializationType;
	
	/** A list of parsing errors if occurred */
	private List<String> structuralValidationErrors;

	/**
	 * Default constructor instantiating object with null values
	 */
	public JWSJsonSerializationObject() {
	}

	/**
	 * Gets the base64url encoded payload of a signature
	 *
	 * @return {@link String} base64url encoded payload
	 */
	public String getPayload() {
		if (payload == null) {
			payload = Utils.EMPTY_STRING;
		}
		return payload;
	}

	/**
	 * Sets the base64url encoded payload of a signature
	 *
	 * @param encodedPayload {@link String} base64url encoded payload
	 */
	public void setPayload(String encodedPayload) {
		this.payload = encodedPayload;
	}

	/**
	 * Returns JWS signatures
	 *
	 * @return a list of {@link JWS}s
	 */
	public List<JWS> getSignatures() {
		if (signatures == null) {
			signatures = new ArrayList<>();
		}
		return signatures;
	}

	/**
	 * Sets a list of signatures
	 *
	 * @param signatures a list of {@link JWS}
	 */
	public void setSignatures(List<JWS> signatures) {
		this.signatures = signatures;
	}

	/**
	 * Gets the used {@code JWSSerializationType} for the signature
	 *
	 * @return {@link JWSSerializationType}
	 */
	public JWSSerializationType getJWSSerializationType() {
		return jwsSerializationType;
	}

	/**
	 * Sets the {@code JWSSerializationType}
	 *
	 * @param jwsSerializationType {@link JWSSerializationType}
	 */
	public void setJWSSerializationType(JWSSerializationType jwsSerializationType) {
		this.jwsSerializationType = jwsSerializationType;
	}

	/**
	 * Returns a list of errors occurred during the structure (schema) validation
	 *
	 * @return a list of {@link String} error messages, empty list if no errors have been found
	 */
	public List<String> getStructuralValidationErrors() {
		if (Utils.isCollectionNotEmpty(structuralValidationErrors)) {
			return structuralValidationErrors;
		}
		return Collections.emptyList();
	}

	/**
	 * Sets a list of errors occurred during the structure (schema) validation
	 *
	 * @param structuralValidationErrors a list of {@link String} error messages
	 */
	public void setStructuralValidationErrors(List<String> structuralValidationErrors) {
		this.structuralValidationErrors = structuralValidationErrors;
	}

	/**
	 * Checks if the signature structure validation succeeded
	 *
	 * @return TRUE if the structure validation succeeded, FALSE otherwise
	 */
	public boolean isValid() {
		return Utils.isCollectionEmpty(structuralValidationErrors);
	}

}
