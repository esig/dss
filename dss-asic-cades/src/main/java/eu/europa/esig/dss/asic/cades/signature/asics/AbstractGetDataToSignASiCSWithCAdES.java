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
import eu.europa.esig.dss.asic.common.signature.asics.AbstractGetDataToSignASiCS;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractGetDataToSignASiCSWithCAdES extends AbstractGetDataToSignASiCS {

	protected String getSignatureFileName(final ASiCParameters asicParameters) {
		if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
			return "META-INF/" + asicParameters.getSignatureFileName();
		}
		return "META-INF/signature.p7s";
	}

	protected String getTimestampFileName() {
		return "META-INF/timestamp.tst";
	}

}
