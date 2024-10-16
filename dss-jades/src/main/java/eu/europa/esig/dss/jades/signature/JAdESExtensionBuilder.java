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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * The abstract class allowing the signature extension
 */
public abstract class JAdESExtensionBuilder {

	/**
	 * Default constructor
	 */
	protected JAdESExtensionBuilder() {
		// empty
	}

	/**
	 * Checks if the type of etsiU components is consistent
	 *
	 * @param jws {@link JWS} to check
	 * @param isBase64UrlEtsiUComponents if the new component shall be base64url encoded
	 */
	protected void assertEtsiUComponentsConsistent(JWS jws, boolean isBase64UrlEtsiUComponents) {
		List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
		if (Utils.isCollectionNotEmpty(etsiU)) {
			if (!DSSJsonUtils.checkComponentsUnicity(etsiU)) {
				throw new IllegalInputException("Extension is not possible, because components of the 'etsiU' header have "
						+ "not common format! Shall be all Strings or Objects.");
			}
			if (DSSJsonUtils.areAllBase64UrlComponents(etsiU) != isBase64UrlEtsiUComponents) {
				throw new IllegalInputException(String.format("Extension is not possible! The encoding of 'etsiU' "
						+ "components shall match! Use jadesSignatureParameters.setBase64UrlEncodedEtsiUComponents(%s)",
						!isBase64UrlEtsiUComponents));
			}
		}
	}

	/**
	 * Checks if the {@code jwsJsonSerializationObject} is valid and can be extended
	 *
	 * @param jwsJsonSerializationObject {@link JWSJsonSerializationObject} to check
	 */
	protected void assertJWSJsonSerializationObjectValid(JWSJsonSerializationObject jwsJsonSerializationObject) {
		if (jwsJsonSerializationObject == null) {
			throw new IllegalInputException("The provided document is not a valid JAdES signature! Unable to extend.");
		}
		if (Utils.isCollectionEmpty(jwsJsonSerializationObject.getSignatures())) {
			throw new IllegalInputException("There is no signature to extend!");
		}
		if (!jwsJsonSerializationObject.isValid()) {
			throw new IllegalInputException(String.format("Signature extension is not supported for invalid RFC 7515 files "
							+ "(shall be a Serializable JAdES signature). Reason(s) : %s",
					jwsJsonSerializationObject.getStructuralValidationErrors()));
		}
	}

	/**
	 * Checks if the given {@code jwsJsonSerializationObject} can be extended
	 *
	 * @param jwsJsonSerializationObject {@link JWSJsonSerializationObject} to check
	 */
	protected void assertJSONSerializationObjectMayBeExtended(JWSJsonSerializationObject jwsJsonSerializationObject) {
		assertJWSJsonSerializationObjectValid(jwsJsonSerializationObject);

		JWSSerializationType jwsSerializationType = jwsJsonSerializationObject.getJWSSerializationType();
		if (!JWSSerializationType.JSON_SERIALIZATION.equals(jwsSerializationType) &&
				!JWSSerializationType.FLATTENED_JSON_SERIALIZATION.equals(jwsSerializationType)) {
			throw new IllegalInputException("The extended signature shall have JSON Serialization (or Flattened) type! " +
					"Use JWSConverter to convert the signature.");
		}
	}

}
