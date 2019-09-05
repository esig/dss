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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * This interface defines the factory to create a {@link DocumentValidator} for
 * a given {@link DSSDocument}
 */
public interface DocumentValidatorFactory {

	/**
	 * This method tests if the current implementation of {@link DocumentValidator}
	 * supports the given document
	 * 
	 * @param document
	 *                 the document to be tested
	 * @return true, if the {@link DocumentValidator} supports the given document
	 */
	boolean isSupported(DSSDocument document);

	/**
	 * This methods instantiates a {@link DocumentValidator} with the given document
	 * 
	 * @param document
	 *                 the document to be used for the {@link DocumentValidator}
	 *                 creation
	 * @return an instance of {@link DocumentValidator} with the document
	 */
	SignedDocumentValidator create(DSSDocument document);

}
