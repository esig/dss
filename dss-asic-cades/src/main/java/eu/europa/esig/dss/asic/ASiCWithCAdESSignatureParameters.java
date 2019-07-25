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
package eu.europa.esig.dss.asic;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;

public class ASiCWithCAdESSignatureParameters extends CAdESSignatureParameters {

	private static final long serialVersionUID = -830012801924753709L;

	/**
	 * The object representing the parameters related to ASiC from of the signature.
	 */
	private ASiCParameters aSiCParams = new ASiCParameters();

	public ASiCParameters aSiC() {
		return aSiCParams;
	}

	@Override
	public void setSignatureLevel(SignatureLevel signatureLevel) {
		if (signatureLevel == null || SignatureForm.CAdES != signatureLevel.getSignatureForm()) {
			throw new IllegalArgumentException("Only CAdES form is allowed !");
		}
		super.setSignatureLevel(signatureLevel);
	}

}
