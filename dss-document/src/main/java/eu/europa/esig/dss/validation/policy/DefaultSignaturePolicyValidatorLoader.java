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

import eu.europa.esig.dss.validation.SignaturePolicy;

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * Loads a relevant {@code SignaturePolicyValidator} based on the policy content
 *
 */
public class DefaultSignaturePolicyValidatorLoader implements SignaturePolicyValidatorLoader {

    /**
     * The validator to be used when only a basic validation according to the signature format is required
     *
     * NOTE: can be null (the best corresponding validator will be loaded)
     */
    private SignaturePolicyValidator defaultSignaturePolicyValidator;

    /**
     * Default constructor instantiating object with null SignaturePolicyValidator
     */
    public DefaultSignaturePolicyValidatorLoader() {
        // empty
    }

    /**
     * This method sets a {@code SignaturePolicyValidator} to be used for default signature policy processing
     * according to the signature format (when {@code SignaturePolicy.hashAsInTechnicalSpecification == false})
     *
     * @param defaultSignaturePolicyValidator {@link SignaturePolicyValidator}
     */
    public void setDefaultSignaturePolicyValidator(SignaturePolicyValidator defaultSignaturePolicyValidator) {
        this.defaultSignaturePolicyValidator = defaultSignaturePolicyValidator;
    }

    /**
     * Loads with a ServiceLoader and returns the relevant validator for a {@code SignaturePolicy}
     *
     * @param signaturePolicy {@link SignaturePolicy} to get a relevant validator for
     * @return {@link SignaturePolicyValidator}
     */
    @Override
    public SignaturePolicyValidator loadValidator(final SignaturePolicy signaturePolicy) {
        SignaturePolicyValidator validator = null;
        if (defaultSignaturePolicyValidator != null && !signaturePolicy.isHashAsInTechnicalSpecification()) {
            validator = defaultSignaturePolicyValidator;

        } else {
            ServiceLoader<SignaturePolicyValidator> loader = ServiceLoader.load(SignaturePolicyValidator.class);
            Iterator<SignaturePolicyValidator> validatorOptions = loader.iterator();

            if (validatorOptions.hasNext()) {
                for (SignaturePolicyValidator signaturePolicyValidator : loader) {
                    if (signaturePolicyValidator.canValidate(signaturePolicy)) {
                        validator = signaturePolicyValidator;
                        break;
                    }
                }
            }
            if (validator == null) {
                // if not empty and no other implementation is found for ASN1 signature policies
                validator = new BasicASNSignaturePolicyValidator();
            }
        }
        return validator;
    }

}
