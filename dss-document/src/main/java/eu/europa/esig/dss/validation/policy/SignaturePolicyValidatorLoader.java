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
package eu.europa.esig.dss.validation.policy;

import java.util.Iterator;
import java.util.ServiceLoader;

import eu.europa.esig.dss.validation.SignaturePolicy;

/**
 * Loads a relevant {@code SignaturePolicyValidator} for the provided {@code SignaturePolicy}
 *
 */
public class SignaturePolicyValidatorLoader {
	
	private final SignaturePolicy signaturePolicy;
	
	public SignaturePolicyValidatorLoader(SignaturePolicy signaturePolicy) {
		this.signaturePolicy = signaturePolicy;
	}
	
	/**
	 * Loads with a ServiceLoader and returns the relevant validator for a {@code SignaturePolicy}
	 * 
	 * @return {@link SignaturePolicyValidator}
	 */
	public SignaturePolicyValidator loadValidator() {
		ServiceLoader<SignaturePolicyValidator> loader = ServiceLoader.load(SignaturePolicyValidator.class);
		Iterator<SignaturePolicyValidator> validatorOptions = loader.iterator();

		SignaturePolicyValidator validator = null;
		if (validatorOptions.hasNext()) {
			for (SignaturePolicyValidator signaturePolicyValidator : loader) {
				signaturePolicyValidator.setSignaturePolicy(signaturePolicy);
				if (signaturePolicyValidator.canValidate()) {
					validator = signaturePolicyValidator;
					break;
				}
			}
		}

		if (validator == null) {
			// if not empty and no other implementation is found for ASN1 signature policies
			validator = new BasicASNSignaturePolicyValidator();
			validator.setSignaturePolicy(signaturePolicy);
		}
		
		return validator;
	}

}
