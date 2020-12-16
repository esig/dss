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
package eu.europa.esig.dss.asic.xades.signature.asics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public class DataToSignASiCSWithXAdESFromFilesTest {

	private static final Logger LOG = LoggerFactory.getLogger(DataToSignASiCSWithXAdESFromFilesTest.class);

	@Test
	public void zipContentEquals() {
		Date now = new Date();
		ASiCParameters asicParameters = new ASiCParameters();
		List<DSSDocument> filesToBeSigned = new ArrayList<>();
		filesToBeSigned.add(new InMemoryDocument("Hello".getBytes(), "test.xml"));
		filesToBeSigned.add(new InMemoryDocument("Bye".getBytes(), "test2.xml"));
		DataToSignASiCSWithXAdESFromFiles dataToSign = new DataToSignASiCSWithXAdESFromFiles(filesToBeSigned, now, asicParameters);
		assertNotNull(dataToSign);

		List<DSSDocument> toBeSigned = dataToSign.getToBeSigned();
		assertEquals(1, toBeSigned.size());
		DSSDocument dssDocument = toBeSigned.get(0);
		assertEquals("package.zip", dssDocument.getName());

		byte[] byteArray = DSSUtils.toByteArray(dssDocument);
		LOG.info(new String(byteArray));
		String base64 = Utils.toBase64(byteArray);
		LOG.info(base64);

		String digest = dssDocument.getDigest(DigestAlgorithm.SHA256);

		LOG.info(digest);

		DataToSignASiCSWithXAdESFromFiles dataToSign2 = new DataToSignASiCSWithXAdESFromFiles(filesToBeSigned, now, asicParameters);
		DSSDocument twice = dataToSign2.getToBeSigned().get(0);

		String digestTwice = twice.getDigest(DigestAlgorithm.SHA256);

		String base64twice = Utils.toBase64(DSSUtils.toByteArray(twice));
		LOG.info(base64twice);
		LOG.info(digestTwice);

		assertEquals(base64, base64twice);
		assertTrue(Utils.areStringsEqual(digest, digestTwice));
	}
}
