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
package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.signature.asics.AbstractGetDataToSignASiCS;
import eu.europa.esig.dss.utils.Utils;

/**
 * An abstract class to generate a DataToSign with ASiC-S with CAdES
 */
public abstract class AbstractGetDataToSignASiCSWithCAdES extends AbstractGetDataToSignASiCS {

	/** The default signature filename */
	private static final String SIGNATURE_FILENAME = ASiCUtils.META_INF_FOLDER + "signature.p7s";

	/** The default timestamp filename */
	private static final String TIMESTAMP_FILENAME = ASiCUtils.META_INF_FOLDER + "timestamp.tst";

	/** The parameters to use */
	protected final ASiCParameters asicParameters;

	/**
	 * The default constructor
	 *
	 * @param asicParameters {@link ASiCParameters}
	 */
	protected AbstractGetDataToSignASiCSWithCAdES(final ASiCParameters asicParameters) {
		this.asicParameters = asicParameters;
	}

	/**
	 * Returns the expected signature filename
	 *
	 * @return {@link String} singature filename
	 */
	protected String getSignatureFileName() {
		if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
			return ASiCUtils.META_INF_FOLDER + asicParameters.getSignatureFileName();
		}
		return SIGNATURE_FILENAME;
	}

	/**
	 * Returns the timestamp filename
	 *
	 * @return {@link String} timestamp filename
	 */
	protected String getTimestampFileName() {
		return TIMESTAMP_FILENAME;
	}

}
