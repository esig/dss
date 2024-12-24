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
package eu.europa.esig.dss.xades.requirements;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.xpath.XPathExpressionException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESBaselineLTTest extends XAdESBaselineTTest {

	@BeforeEach
	@Override
	void init() throws Exception {
		super.init();
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
		XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
		// Default processing
		// signatureParameters.setValidationDataEncapsulationStrategy(ValidationDataEncapsulationStrategy.CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA);
		return signatureParameters;
	}

	/**
	 * Checks UnsignedSignatureProperties present for T/LT/LTA levels
	 */
	@Override
	protected void checkUnsignedProperties() throws XPathExpressionException {
		super.checkUnsignedProperties();

		assertTrue(checkCertificateValuesPresent());
		assertTrue(checkRevocationValuesPresent());
		assertTrue(checkTimeStampValidationDataPresent());
		assertFalse(checkAnyValidationDataPresent());
	}

}
