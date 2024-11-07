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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzerFactory;

/**
 * This class returns a relevant validator for an ASiC with XAdES container validation
 *
 */
public class ASiCContainerWithXAdESAnalyzerFactory implements DocumentAnalyzerFactory {

	/**
	 * Default constructor
	 */
	public ASiCContainerWithXAdESAnalyzerFactory() {
		// empty
	}

	@Override
	public boolean isSupported(DSSDocument document) {
		ASiCContainerWithXAdESAnalyzer validator = new ASiCContainerWithXAdESAnalyzer();
		return validator.isSupported(document);
	}

	/**
	 * Verifies whether the provided {@code ASiCContent} is supported by the underlying validator's class
	 *
	 * @param asicContent {@link ASiCContent}
	 * @return TRUE if the ASiC Content is supported, FALSE otherwise
	 */
	public boolean isSupported(ASiCContent asicContent) {
		ASiCContainerWithXAdESAnalyzer validator = new ASiCContainerWithXAdESAnalyzer();
		return validator.isSupported(asicContent);
	}

	@Override
	public DocumentAnalyzer create(DSSDocument document) {
		return new ASiCContainerWithXAdESAnalyzer(document);
	}

	/**
	 * Creates a {@code DocumentAnalyzer} for the given {@code asicContent}
	 *
	 * @param asicContent {@link ASiCContent} to be validated
	 * @return {@link DocumentAnalyzer}
	 */
	public DocumentAnalyzer create(ASiCContent asicContent) {
		return new ASiCContainerWithXAdESAnalyzer(asicContent);
	}

}
