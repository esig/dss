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
package eu.europa.esig.dss.spi.validation.scope;

import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

import java.util.List;

/**
 * Builds a list of {@code SignatureScope}s from an {@code AdvancedSignature}
 *
 * @param <T> {@code AdvancedSignature} implementation
 */
public interface SignatureScopeFinder<T extends AdvancedSignature> {

	/**
	 * Returns a list of {@code SignatureScope}s from a signature
	 *
	 * @param advancedSignature {@link AdvancedSignature} to get signatureScopes for
	 * @return a list of {@link SignatureScope}s
	 */
	List<SignatureScope> findSignatureScope(final T advancedSignature);
	
}
