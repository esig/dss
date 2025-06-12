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
package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.model.DSSDocument;

import java.io.InputStream;

/**
 * Interface containing methods to load a {@code eu.europa.esig.dss.model.policy.ValidationPolicy} from a file
 *
 */
public interface ValidationPolicyFactory {

    /**
     * Evaluates whether the validation policy {@code DSSDocument} is supported by the current implementation
     *
     * @param validationPolicyDocument {@link DSSDocument} containing validation policy
     * @return TRUE if the file is supported, FALSE otherwise
     */
    boolean isSupported(DSSDocument validationPolicyDocument);

    /**
     * Loads a default validation policy provided by the implementation
     *
     * @return {@link ValidationPolicy}
     */
    ValidationPolicy loadDefaultValidationPolicy();

    /**
     * Loads a validation policy from a {@code DSSDocument} provided to the method
     *
     * @param validationPolicyDocument {@link DSSDocument}
     * @return {@link ValidationPolicy}
     */
    ValidationPolicy loadValidationPolicy(DSSDocument validationPolicyDocument);

    /**
     * Loads a validation policy from an {@code InputStream} provided to the method
     *
     * @param validationPolicyInputStream {@link InputStream}
     * @return {@link ValidationPolicy}
     */
    ValidationPolicy loadValidationPolicy(InputStream validationPolicyInputStream);

}
