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
package eu.europa.esig.dss.tsl.download;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XmlDownloadTaskTest {

	@Test
	void nullResult() {
		Map<String, byte[]> dataMap = new HashMap<>();
		dataMap.put("null", null);
		dataMap.put("empty-array", new byte[] {});
		dataMap.put("0", new byte[] { 0 });
		MemoryDataLoader memoryDataLoader = new MemoryDataLoader(dataMap);

		DSSFileLoader dataLoader = new FileCacheDataLoader(memoryDataLoader);
		for (String url : dataMap.keySet()) {
			XmlDownloadTask task = new XmlDownloadTask(dataLoader, url);
			assertThrows(DSSException.class, task::get);
		}
	}

	@Test
	void nonNullResults() {
		Map<String, byte[]> dataMap = new HashMap<>();

		byte[] sampleByteArray = DSSUtils.toByteArray(new FileDocument(new File("src/test/resources/sample.xml")));
		dataMap.put("sample", sampleByteArray);
		dataMap.put("sample-spaces", DSSUtils.toByteArray(new FileDocument(new File("src/test/resources/sample-spaces.xml"))));
		dataMap.put("sample-comment", DSSUtils.toByteArray(new FileDocument(new File("src/test/resources/sample-comment.xml"))));
		byte[] sampleWithBomByteArray = DSSUtils.toByteArray(new FileDocument(new File("src/test/resources/sample-bom.xml")));
		dataMap.put("sample-bom", sampleWithBomByteArray);

		assertNotEquals(DSSUtils.getMD5Digest(sampleByteArray), DSSUtils.getMD5Digest(sampleWithBomByteArray));

		MemoryDataLoader memoryDataLoader = new MemoryDataLoader(dataMap);
		FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader(memoryDataLoader);
		fileCacheDataLoader.setCacheExpirationTime(0);
		
		XmlDownloadResult first = null;
		for (String url : dataMap.keySet()) {
			XmlDownloadTask task = new XmlDownloadTask(fileCacheDataLoader, url);
			XmlDownloadResult downloadResult = task.get();
			assertNotNull(downloadResult);
			assertNotNull(downloadResult.getDSSDocument());
			assertNotNull(downloadResult.getDigest());
			assertNotNull(downloadResult.getDigest().getAlgorithm());
			assertNotNull(downloadResult.getDigest().getValue());
			if (first == null) {
				first = downloadResult;
			} else {
				assertEquals(first.getDigest(), downloadResult.getDigest());
			}
		}

		dataMap.put("sample-diff", DSSUtils.toByteArray(new FileDocument(new File("src/test/resources/sample-diff.xml"))));
		memoryDataLoader = new MemoryDataLoader(dataMap);
		fileCacheDataLoader = new FileCacheDataLoader(memoryDataLoader);
		
		XmlDownloadTask task = new XmlDownloadTask(fileCacheDataLoader, "sample-diff");
		XmlDownloadResult downloadResultDiff = task.get();
		assertNotNull(downloadResultDiff);
		assertNotNull(downloadResultDiff.getDigest());
		assertNotEquals(first.getDigest(), downloadResultDiff.getDigest());
	}

}
