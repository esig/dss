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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzerFactory;

/**
 * Loads the relevant Validator to process a given JWS signature
 *
 */
public class JWSDocumentAnalyzerFactory implements DocumentAnalyzerFactory {

	/**
	 * Default constructor
	 */
	public JWSDocumentAnalyzerFactory() {
		// empty
	}

	@Override
	public boolean isSupported(DSSDocument document) {
		JWSCompactDocumentAnalyzer compactValidator = new JWSCompactDocumentAnalyzer();
		if (compactValidator.isSupported(document)) {
			return true;
		}

		JWSSerializationAnalyzerValidator serializationValidator = new JWSSerializationAnalyzerValidator();
		if (serializationValidator.isSupported(document)) {
			return true;
		}

		return false;
	}

	@Override
	public AbstractJWSDocumentAnalyzer create(DSSDocument document) {

		JWSCompactDocumentAnalyzer compactValidator = new JWSCompactDocumentAnalyzer();
		if (compactValidator.isSupported(document)) {
			return new JWSCompactDocumentAnalyzer(document);
		}

		JWSSerializationAnalyzerValidator serializationValidator = new JWSSerializationAnalyzerValidator();
		if (serializationValidator.isSupported(document)) {
			return new JWSSerializationAnalyzerValidator(document);
		}

		throw new IllegalArgumentException("Not supported document");
	}

}