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
package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class CMSTimestampValidatorTest extends PKIFactoryAccess {

	@Test
	public void testValidator() throws Exception {

		TSPSource tspSource = getGoodTsa();

		byte[] data = new byte[] { 1, 2, 3 };
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, data));

		CMSTimestampValidator validator = new CMSTimestampValidator(new InMemoryDocument(timeStampResponse.getEncoded()));
		validator.setTimestampedData(new InMemoryDocument(data));
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		assertTrue(Utils.isCollectionEmpty(validator.getSignatures()));

		TimestampToken timestamp = validator.getTimestamp();
		assertNotNull(timestamp);
		assertTrue(timestamp.isMessageImprintDataFound());
		assertTrue(timestamp.isMessageImprintDataIntact());
	}

	@Override
	protected String getSigningAlias() {
		// not for signing
		return null;
	}

}
