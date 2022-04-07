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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.xades.OpenDocumentSupportUtils;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * A class to generate a DataToSign for an OpenDocument signing
 */
public class DataToSignOpenDocumentHelper extends DataToSignASiCEWithXAdESHelper {

	/** The default signature filename */
	private static final String ZIP_OPEN_DOCUMENT_METAINF_XADES_SIGNATURE =
			ASiCUtils.META_INF_FOLDER + "documentsignatures.xml";

	/**
	 * The default constructor
	 *
	 * @param asicContent    {@link ASiCContent}
	 * @param asicParameters {@link ASiCParameters}
	 */
	public DataToSignOpenDocumentHelper(final ASiCContent asicContent, final ASiCParameters asicParameters) {
		super(asicContent, asicParameters);
	}

	@Override
	public List<DSSDocument> getToBeSigned() {
		return OpenDocumentSupportUtils.getOpenDocumentCoverage(asicContent);
	}

	@Override
	public String getSignatureFilename() {
		return ZIP_OPEN_DOCUMENT_METAINF_XADES_SIGNATURE;
	}

	@Override
	public boolean isOpenDocument() {
		return true;
	}

}
