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
package eu.europa.esig.dss;

import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.utils.Utils;

/**
 * Unit test to fix https://esig-dss.atlassian.net/browse/DSS-672
 */
class AbstractSignatureParametersTest {

	private static final Logger logger = LoggerFactory.getLogger(AbstractSignatureParametersTest.class);

	@Test
	void testToString() {
		CommonSignatureParamaters commonSignatureParamaters = new CommonSignatureParamaters();
		String parametersString = commonSignatureParamaters.toString();
		logger.info(parametersString);
		assertTrue(Utils.isStringNotEmpty(parametersString));
		assertTrue(parametersString.contains("AbstractSerializableSignatureParameters ["));
	}

	@SuppressWarnings("serial")
	private static class CommonSignatureParamaters extends AbstractSignatureParameters<TimestampParameters> {
	}
	
}
