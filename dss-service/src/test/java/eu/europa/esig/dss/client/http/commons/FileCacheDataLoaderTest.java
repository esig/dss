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
package eu.europa.esig.dss.client.http.commons;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import eu.europa.esig.dss.client.http.MemoryDataLoader;

public class FileCacheDataLoaderTest {

	static final String URL_TO_LOAD = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";

	@Rule
	public TemporaryFolder testFolder = new TemporaryFolder();

	private FileCacheDataLoader dataLoader;
	private File cacheDirectory;

	@Before
	public void setUp() throws Exception {
		cacheDirectory = testFolder.newFolder("dss-file-cache");
		dataLoader = new FileCacheDataLoader();
		dataLoader.setDataLoader(new CommonsDataLoader());
		dataLoader.setFileCacheDirectory(cacheDirectory);
	}

	@Test(expected = NullPointerException.class)
	public void testNotDefineSubDataLoader() {
		FileCacheDataLoader fcdl = new FileCacheDataLoader();
		fcdl.get(URL_TO_LOAD);
	}

	@Test
	public void getUrl_whenExpirationTimeIsNotSet_useCachedFile() throws Exception {
		long cacheCreationTime = getUrlAndReturnCacheCreationTime();
		waitOneSecond();
		long newCacheCreationTime = getUrlAndReturnCacheCreationTime();
		assertEquals(cacheCreationTime, newCacheCreationTime);
	}

	@Test
	public void getUrl_whenCacheIsNotExpired_useCachedFile() throws Exception {
		dataLoader.setCacheExpirationTime(2000L);
		long cacheCreationTime = getUrlAndReturnCacheCreationTime();
		waitOneSecond();
		long newCacheCreationTime = getUrlAndReturnCacheCreationTime();
		assertEquals(cacheCreationTime, newCacheCreationTime);
	}

	@Test
	public void getUrl_whenCacheIsExpired_downloadNewCopy() throws Exception {
		dataLoader.setCacheExpirationTime(500L);
		long cacheCreationTime = getUrlAndReturnCacheCreationTime();
		waitOneSecond();
		long newCacheCreationTime = getUrlAndReturnCacheCreationTime();
		assertTrue(cacheCreationTime < newCacheCreationTime);
	}

	@Test
	public void testNotNetworkProtocol() throws IOException {
		cacheDirectory = testFolder.newFolder();

		FileCacheDataLoader specificDataLoader = new FileCacheDataLoader();
		specificDataLoader.setDataLoader(new MemoryDataLoader(new HashMap<String, byte[]>()));
		specificDataLoader.setFileCacheDirectory(cacheDirectory);

		assertNull(specificDataLoader.get("1.2.3.4.5"));
		assertNull(specificDataLoader.post("1.2.3.4.5", new byte[] { 1, 2, 3 }));

		specificDataLoader.setResourceLoader(new ResourceLoader(FileCacheDataLoaderTest.class));
		assertNotNull(specificDataLoader.get("/logback.xml"));
	}

	private long getUrlAndReturnCacheCreationTime() {
		byte[] bytesArray = dataLoader.get(URL_TO_LOAD);
		assertTrue(bytesArray.length > 0);
		File cachedFile = getCachedFile(cacheDirectory);
		return cachedFile.lastModified();
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
