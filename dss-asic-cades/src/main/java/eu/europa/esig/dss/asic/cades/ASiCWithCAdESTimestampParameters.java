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
package eu.europa.esig.dss.asic.cades;

import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.util.Date;

/**
 * Defines TimestampParameters to deal with ASiC with CAdES timestamp creation
 */
@SuppressWarnings("serial")
public class ASiCWithCAdESTimestampParameters extends CAdESTimestampParameters implements ASiCWithCAdESCommonParameters {

	/** Time is used to set the DateTime for created ZIP entries */
	private Date zipCreationDate = new Date();
	
	/**
	 * The object representing the parameters related to ASiC for the timestamp.
	 */
	private ASiCParameters asicParams = new ASiCParameters();

	@Override
	public ASiCParameters aSiC() {
		return asicParams;
	}

	/**
	 * The empty constructor
	 */
	public ASiCWithCAdESTimestampParameters() {
		// empty
	}

	/**
	 * The constructor defining a {@code DigestAlgorithm}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to set
	 */
	public ASiCWithCAdESTimestampParameters(DigestAlgorithm digestAlgorithm) {
		super(digestAlgorithm);
	}

	/**
	 * The constructor defining a {@code DigestAlgorithm} and {@code ASiCParameters}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to set
	 * @param asicParams {@link ASiCParameters} to set
	 */
	public ASiCWithCAdESTimestampParameters(DigestAlgorithm digestAlgorithm, ASiCParameters asicParams) {
		super(digestAlgorithm);
		this.asicParams = asicParams;
	}

	@Override
	public Date getZipCreationDate() {
		return zipCreationDate;
	}

	/**
	 * Sets ZIP creation date, used to define a creation date for ZIP container entries
	 *
	 * @param zipCreationDate {@link Date}
	 */
	public void setZipCreationDate(Date zipCreationDate) {
		this.zipCreationDate = zipCreationDate;
	}

}
