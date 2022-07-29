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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;

/**
 * Parameters to create a JAdES counter-signature
 *
 */
public class JAdESCounterSignatureParameters extends JAdESSignatureParameters implements SerializableCounterSignatureParameters {
	
	private static final long serialVersionUID = 369732165720690096L;

	/**
	 * Signature Id to be counter-signed
	 */
	private String signatureIdToCounterSign;

	/**
	 * Default constructor instantiating object with null signature id to be counter-signed
	 */
	public JAdESCounterSignatureParameters() {
	}

	@Override
	public String getSignatureIdToCounterSign() {
		return signatureIdToCounterSign;
	}
	
	@Override
	public void setSignatureIdToCounterSign(String signatureId) {
		this.signatureIdToCounterSign = signatureId;
	}

}
