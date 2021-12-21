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
package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.signature.GetDataToSignASiCWithCAdESHelper;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.signature.AbstractGetDataToSignHelper;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.Collections;
import java.util.List;

/**
 * An abstract class to generate a DataToSign with ASiC-E with CAdES
 */
public class DataToSignASiCEWithCAdESHelper extends AbstractGetDataToSignHelper implements GetDataToSignASiCWithCAdESHelper {

	/** The cached ToBeSigned document */
	private final DSSDocument toBeSigned;

	/** ASiC container parameters */
	private final ASiCParameters asicParameters;

	/**
	 * The default constructor
	 *
	 * @param asicContent {@link ASiCContent}
	 * @param toBeSigned {@link DSSDocument}
	 * @param asicParameters {@link ASiCParameters}
	 */
	public DataToSignASiCEWithCAdESHelper(final ASiCContent asicContent, final DSSDocument toBeSigned,
										  final ASiCParameters asicParameters) {
		super(asicContent);
		this.toBeSigned = toBeSigned;
		this.asicParameters = asicParameters;
	}

	@Override
	public DSSDocument getToBeSigned() {
		return toBeSigned;
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return Collections.emptyList();
	}

	@Override
	public String getSignatureFilename() {
		return ASiCWithCAdESUtils.getSignatureFileName(getASiCContent().getSignatureDocuments(), asicParameters.getSignatureFileName());
	}

	@Override
	public String getTimestampFilename() {
		return ASiCWithCAdESUtils.getTimestampFileName(getASiCContent().getTimestampDocuments());
	}

}
