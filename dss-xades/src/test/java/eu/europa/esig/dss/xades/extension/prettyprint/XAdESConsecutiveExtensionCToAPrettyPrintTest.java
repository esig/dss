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
package eu.europa.esig.dss.xades.extension.prettyprint;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.extension.AbstractXAdESConsecutiveExtension;

class XAdESConsecutiveExtensionCToAPrettyPrintTest extends AbstractXAdESConsecutiveExtension<XAdESSignatureParameters> {

	@Override
	protected DSSDocument getOriginalDocument() {
		return new FileDocument("src/test/resources/sample.xml");
	}

	@Override
	protected SignatureLevel getFirstSignSignatureLevel() {
		signatureParameters.setPrettyPrint(true);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_C);
		return SignatureLevel.XAdES_C;
	}

	@Override
	protected SignatureLevel getSecondSignSignatureLevel() {
		signatureParameters.setPrettyPrint(false);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_X);
		return SignatureLevel.XAdES_X;
	}

	@Override
	protected SignatureLevel getThirdSignSignatureLevel() {
		signatureParameters.setPrettyPrint(true);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_XL);
		return SignatureLevel.XAdES_XL;
	}

	@Override
	protected SignatureLevel getFourthSignSignatureLevel() {
		signatureParameters.setPrettyPrint(false);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_A);
		return SignatureLevel.XAdES_A;
	}	

}