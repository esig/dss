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
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;

import java.util.Date;
import java.util.Objects;

/**
 * Defines SignatureParameters to deal with ASiC with CAdES signature creation/extension
 */
public class ASiCWithCAdESSignatureParameters extends CAdESSignatureParameters implements ASiCWithCAdESCommonParameters {

	private static final long serialVersionUID = -830012801924753709L;

	/**
	 * The object representing the parameters related to ASiC for the signature.
	 */
	private ASiCParameters asicParams = new ASiCParameters();

	/**
	 * Default constructor instantiating object with default ASiCParameters
	 */
	public ASiCWithCAdESSignatureParameters() {
		// empty
	}

	@Override
	public ASiCParameters aSiC() {
		return asicParams;
	}

	@Override
	public void setSignatureLevel(SignatureLevel signatureLevel) {
		if (signatureLevel == null || SignatureForm.CAdES != signatureLevel.getSignatureForm()) {
			throw new IllegalArgumentException("Only CAdES form is allowed !");
		}
		super.setSignatureLevel(signatureLevel);
	}

	@Override
	public Date getZipCreationDate() {
		return bLevel().getSigningDate();
	}

	@Override
	public String toString() {
		return "ASiCWithCAdESSignatureParameters [" +
				"asicParams=" + asicParams +
				"] " + super.toString();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		if (!super.equals(o)) return false;

		ASiCWithCAdESSignatureParameters that = (ASiCWithCAdESSignatureParameters) o;
		return Objects.equals(asicParams, that.asicParams);
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = 31 * result + Objects.hashCode(asicParams);
		return result;
	}

}
