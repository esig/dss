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
package eu.europa.esig.dss.asic.cades;

import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.io.Serializable;
import java.util.Date;

/**
 * The interface defining common parameters for an ASiC with CAdES container for signature/timestamp creation
 */
public interface ASiCWithCAdESCommonParameters extends Serializable {

	/**
	 * Returns ASiC container parameters
	 * 
	 * @return {@link ASiCParameters}
	 */
	ASiCParameters aSiC();
	
	/**
	 * Returns a DigestAlgorithm to be used to hash a data to be timestamped
	 * 
	 * @return {@link DigestAlgorithm}
	 */
	DigestAlgorithm getDigestAlgorithm();
	
	/**
	 * Returns a signing date
	 *
	 * @return {@link Date}
	 */
	Date getZipCreationDate();

}
