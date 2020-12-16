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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.validation.AbstractSignatureIdentifierBuilder;
import eu.europa.esig.dss.validation.AdvancedSignature;

/**
 * The DSS identifier for a JAdES signature
 */
public class JAdESSignatureIdentifierBuilder extends AbstractSignatureIdentifierBuilder {

	/**
	 * Default constructor
	 *
	 * @param signature {@link JAdESSignature} to get an identifier for
	 */
	public JAdESSignatureIdentifierBuilder(JAdESSignature signature) {
		super(signature);
	}

	@Override
	protected Integer getCounterSignaturePosition(AdvancedSignature masterSignature) {
		JAdESSignature jadesSignature = (JAdESSignature) signature;
		JAdESSignature jadesMasterSignature = (JAdESSignature) masterSignature;
		JAdESAttribute masterCSigAttribute = jadesSignature.getMasterCSigComponent();

		int counter = 0;
		if (masterCSigAttribute != null) {
			for (AdvancedSignature counterSignature : jadesMasterSignature.getCounterSignatures()) {
				JAdESSignature jadesCounterSignature = (JAdESSignature) counterSignature;
				if (masterCSigAttribute.hashCode() == jadesCounterSignature.getMasterCSigComponent().hashCode()) {
					break;
				}
				++counter;
			}
		}
		
		return counter;
	}

	@Override
	protected Integer getSignatureFilePosition() {
		JAdESSignature jadesSignature = (JAdESSignature) signature;
		JWS currentJWS = jadesSignature.getJws();
		JWSJsonSerializationObject jwsJsonSerializationObject = jadesSignature.getJws().getJwsJsonSerializationObject();
		
		int counter = 0;
		if (jwsJsonSerializationObject != null) {
			for (JWS jws : jwsJsonSerializationObject.getSignatures()) {
				if (currentJWS == jws) {
					break;
				}
				++counter;
			}
		}
		
		return counter;
	}

}
