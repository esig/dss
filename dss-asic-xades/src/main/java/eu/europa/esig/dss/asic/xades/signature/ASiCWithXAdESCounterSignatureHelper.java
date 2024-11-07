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
package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.signature.ASiCCounterSignatureHelper;
import eu.europa.esig.dss.asic.xades.extract.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.xades.validation.XMLDocumentAnalyzer;

import java.util.List;

/**
 * The class contains useful methods for ASiC with XAdES counter signature creation
 */
public class ASiCWithXAdESCounterSignatureHelper extends ASiCCounterSignatureHelper {

	/**
	 * The default constructor
	 *
	 * @param asicContainer {@link DSSDocument} representing an ASiC with CAdES container
	 */
	protected ASiCWithXAdESCounterSignatureHelper(DSSDocument asicContainer) {
		super(asicContainer);
	}

	@Override
	protected DefaultASiCContainerExtractor getASiCContainerExtractor() {
		return new ASiCWithXAdESContainerExtractor(asicContainer);
	}

	@Override
	protected DocumentAnalyzer getDocumentAnalyzer(DSSDocument signatureDocument) {
		return new XMLDocumentAnalyzer(signatureDocument);
	}

	@Override
	protected List<DSSDocument> getDetachedDocuments(String signatureFilename) {
		// return all found documents (any document can be signed)
		return getAsicContent().getAllDocuments();
	}

}
