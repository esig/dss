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
package eu.europa.esig.dss.xades.extension;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

class XAdESExtensionLTToLTAWithError500TimestampTest extends AbstractXAdESTestExtension {

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getError500GoodTsa();
	}

	@Override
	protected SignatureLevel getOriginalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LT;
	}

	@Override
	protected SignatureLevel getFinalSignatureLevel() {
		return SignatureLevel.XAdES_BASELINE_LTA;
	}

	@Override
	@Test
	public void extendAndVerify() throws Exception {
		Exception exception = assertThrows(DSSException.class, () -> super.extendAndVerify());
		assertTrue(exception.getMessage().contains("Unable to process POST call for url [" + getPkiFactoryHost() + "/tsa/error-500/good-tsa]"));
	}

}
