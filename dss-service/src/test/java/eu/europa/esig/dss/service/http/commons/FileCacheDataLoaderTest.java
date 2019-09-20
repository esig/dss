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
package eu.europa.esig.dss.service.http.commons;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.utils.Utils;

public class FileCacheDataLoaderTest {

	static final String URL_TO_LOAD = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

	@TempDir
	Path testFolder;

	private FileCacheDataLoader dataLoader;
	private File cacheDirectory;

	@BeforeEach
	public void setUp() throws Exception {
		Path pathToFile = testFolder.resolve("dss-file-cache");
		cacheDirectory = pathToFile.toFile();
		dataLoader = new FileCacheDataLoader();
		dataLoader.setDataLoader(new CommonsDataLoader());
		dataLoader.setFileCacheDirectory(cacheDirectory);
	}

	@Test
	public void testNotDefineSubDataLoader() {
		assertThrows(NullPointerException.class, () -> {
			FileCacheDataLoader fcdl = new FileCacheDataLoader();
			fcdl.get(URL_TO_LOAD);
		});
	}

	@Test
	public void getUrl_whenExpirationTimeIsNotSet_useCachedFile() throws Exception {
		long cacheCreationTime = getUrlAndReturnCacheCreationTime();
		waitOneSecond();
		long newCacheCreationTime = getUrlAndReturnCacheCreationTime();
		assertEquals(cacheCreationTime, newCacheCreationTime);
		getDSSDocumentByUrl();
	}

	@Test
	public void getUrl_whenCacheIsNotExpired_useCachedFile() throws Exception {
		dataLoader.setCacheExpirationTime(2000L);
		long cacheCreationTime = getUrlAndReturnCacheCreationTime();
		waitOneSecond();
		long newCacheCreationTime = getUrlAndReturnCacheCreationTime();
		assertEquals(cacheCreationTime, newCacheCreationTime);
		getDSSDocumentByUrl();
	}

	@Test
	public void getUrl_whenCacheIsExpired_downloadNewCopy() throws Exception {
		dataLoader.setCacheExpirationTime(500L);
		long cacheCreationTime = getUrlAndReturnCacheCreationTime();
		waitOneSecond();
		long newCacheCreationTime = getUrlAndReturnCacheCreationTime();
		assertTrue(cacheCreationTime < newCacheCreationTime);
		getDSSDocumentByUrl();
	}

	@Test
	public void testNotNetworkProtocol() throws IOException {
		Path pathToFolder = testFolder.resolve("");
		cacheDirectory = pathToFolder.toFile();
		FileCacheDataLoader specificDataLoader = new FileCacheDataLoader();
		specificDataLoader.setDataLoader(new MemoryDataLoader(new HashMap<String, byte[]>()));
		specificDataLoader.setFileCacheDirectory(cacheDirectory);

		assertNull(specificDataLoader.get("1.2.3.4.5"));
		assertNull(specificDataLoader.getDocument("1.2.3.4.5"));
		assertNull(specificDataLoader.post("1.2.3.4.5", new byte[] { 1, 2, 3 }));
		specificDataLoader.createFile("1.2.3.4.5", new byte[] { 1, 2, 3 });
		assertNotNull(specificDataLoader.get("1.2.3.4.5"));
		assertNotNull(specificDataLoader.getDocument("1.2.3.4.5"));

		specificDataLoader.setResourceLoader(new ResourceLoader(FileCacheDataLoaderTest.class));
		assertNotNull(specificDataLoader.get("/logback.xml"));
		assertNotNull(specificDataLoader.getDocument("/logback.xml"));
	}
	
	@Test
	public void testGetDSSDocument() {
		DSSDocument dssDocument = getDSSDocumentByUrl();
		assertNotNull(dssDocument.getAbsolutePath());
		assertTrue(Utils.isArrayNotEmpty(DSSUtils.toByteArray(dssDocument)));
	}

	private long getUrlAndReturnCacheCreationTime() {
		byte[] bytesArray = dataLoader.get(URL_TO_LOAD);
		assertTrue(bytesArray.length > 0);
		File cachedFile = getCachedFile(cacheDirectory);
		return cachedFile.lastModified();
	}
	
	private DSSDocument getDSSDocumentByUrl() {
		DSSDocument document = dataLoader.getDocument(URL_TO_LOAD);
		assertNotNull(document);
		return document;
	}

	private File getCachedFile(File cacheDirectory) {
		File cachedFile = null;
		if (cacheDirectory.exists()) {
			File[] files = cacheDirectory.listFiles();
			if (files != null && files.length > 0) {
				cachedFile = files[0];
			}
		}
		return cachedFile;
	}

	private void waitOneSecond() throws InterruptedException {
		Thread.sleep(1000); // Sleeping is necessary to verify changes in the cache creation time
	}
}
