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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.DocumentValidatorFactory;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

/**
 * This class returns a relevant validator for an ASiC with CAdES container validation
 */
public class ASiCContainerWithCAdESValidatorFactory implements DocumentValidatorFactory {

	@Override
	public boolean isSupported(DSSDocument document) {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator();
		return validator.isSupported(document);
	}

	/**
	 * Verifies whether the provided {@code ASiCContent} is supported by the underlying validator's class
	 *
	 * @param asicContent {@link ASiCContent}
	 * @return TRUE if the ASiC Content is supported, FALSE otherwise
	 */
	public boolean isSupported(ASiCContent asicContent) {
		ASiCContainerWithCAdESValidator validator = new ASiCContainerWithCAdESValidator();
		return validator.isSupported(asicContent);
	}

	@Override
	public SignedDocumentValidator create(DSSDocument document) {
		return new ASiCContainerWithCAdESValidator(document);
	}

	/**
	 * Creates a {@code SignedDocumentValidator} for the given {@code asicContent}
	 *
	 * @param asicContent {@link ASiCContent} to be validated
	 * @return {@link SignedDocumentValidator}
	 */
	public SignedDocumentValidator create(ASiCContent asicContent) {
		return new ASiCContainerWithCAdESValidator(asicContent);
	}

}
