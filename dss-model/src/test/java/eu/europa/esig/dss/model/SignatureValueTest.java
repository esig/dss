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
package eu.europa.esig.dss.model;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

class SignatureValueTest {

	private static final Logger LOG = LoggerFactory.getLogger(SignatureValueTest.class);

	@Test
	void testToString() {
		SignatureValue sv = new SignatureValue();
		LOG.info("{}", sv);
		assertEquals("SignatureValue [algorithm=null, value=null]", sv.toString());
		sv.setAlgorithm(SignatureAlgorithm.RSA_SSA_PSS_SHA224_MGF1);
		sv.setValue(new byte[] { 1, 2, 3 });
		LOG.info("{}", sv);
		assertEquals("SignatureValue [algorithm=RSA_SSA_PSS_SHA224_MGF1, value=AQID]", sv.toString());
	}

}
