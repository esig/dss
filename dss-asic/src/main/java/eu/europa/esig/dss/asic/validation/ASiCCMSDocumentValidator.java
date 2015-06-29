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
package eu.europa.esig.dss.asic.validation;

import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.validation.DocumentValidator;

/**
 * Validator for ASiC signature
 *
 *
 *
 *
 *
 *
 */
public class ASiCCMSDocumentValidator extends CMSDocumentValidator {


	/**
	 * This variable defines the sequence of the validator related to a document to validate. It's only used with ASiC-E container
	 */
	private DocumentValidator nextValidator;

	/**
	 * The default constructor for ASiCXMLDocumentValidator.
	 *
	 * @param signature        {@code DSSDocument} representing the signature to validate
	 * @param detachedContents the {@code List} containing the potential signed documents
	 * @throws DSSException
	 */
	public ASiCCMSDocumentValidator(final DSSDocument signature, final List<DSSDocument> detachedContents) throws DSSException {

		super(signature);
		this.detachedContents = detachedContents;
	}

	@Override
	public void setNextValidator(final DocumentValidator validator) {

		nextValidator = validator;
	}

	@Override
	public DocumentValidator getNextValidator() {
		return nextValidator;
	}
}
