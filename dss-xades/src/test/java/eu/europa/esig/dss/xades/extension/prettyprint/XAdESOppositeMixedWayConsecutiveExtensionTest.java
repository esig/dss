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
package eu.europa.esig.dss.xades.extension.prettyprint;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.extension.AbstractXAdESConsecutiveExtension;

public class XAdESOppositeMixedWayConsecutiveExtensionTest extends AbstractXAdESConsecutiveExtension<XAdESSignatureParameters> {

	@Override
	protected DSSDocument getOriginalDocument() {
		return new FileDocument("src/test/resources/sample.xml");
	}

	@Override
	protected SignatureLevel getFirstSignSignatureLevel() {
		signatureParameters.setPrettyPrint(false);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		return SignatureLevel.XAdES_BASELINE_B;
	}

	@Override
	protected SignatureLevel getSecondSignSignatureLevel() {
		signatureParameters.setPrettyPrint(true);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		return SignatureLevel.XAdES_BASELINE_T;
	}

	@Override
	protected SignatureLevel getThirdSignSignatureLevel() {
		signatureParameters.setPrettyPrint(false);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		return SignatureLevel.XAdES_BASELINE_LT;
	}

	@Override
	protected SignatureLevel getFourthSignSignatureLevel() {
		signatureParameters.setPrettyPrint(true);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		return SignatureLevel.XAdES_BASELINE_LTA;
	}	

}