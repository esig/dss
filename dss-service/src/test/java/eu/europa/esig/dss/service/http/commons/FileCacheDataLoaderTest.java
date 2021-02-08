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

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader.DataAndUrl;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.utils.Utils;

public class FileCacheDataLoaderTest {

	static final String URL_TO_LOAD = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";

	@TempDir
	File cacheDirectory;

	private FileCacheDataLoader dataLoader;

	@BeforeEach
	public void setUp() throws Exception {
		dataLoader = new FileCacheDataLoader();
		dataLoader.setDataLoader(new CommonsDataLoader());
		dataLoader.setFileCacheDirectory(cacheDirectory);
	}

	@Test
	public void testNotDefineSubDataLoader() {
		FileCacheDataLoader fcdl = new FileCacheDataLoader();
		assertThrows(NullPointerException.class, () -> fcdl.get(URL_TO_LOAD));
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
		FileCacheDataLoader specificDataLoader = new FileCacheDataLoader();
		specificDataLoader.setDataLoader(new MemoryDataLoader(new HashMap<String, byte[]>()));
		specificDataLoader.setFileCacheDirectory(cacheDirectory);

		assertThrows(DSSException.class, () -> specificDataLoader.get("1.2.3.4.5"));
		assertThrows(DSSException.class, () -> specificDataLoader.getDocument("1.2.3.4.5"));
		assertThrows(DSSException.class, () -> specificDataLoader.post("1.2.3.4.5", new byte[] { 1, 2, 3 }));
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
		assertTrue(Utils.isArrayNotEmpty(DSSUtils.toByteArray(dssDocument)));
	}
	
	@Test
	public void offlineDataLoaderTest() throws IOException {
		File cacheDirectory = new File("target/cache");
		cacheDirectory.mkdirs();
		Files.walk(cacheDirectory.toPath()).map(Path::toFile).forEach(File::delete);
		
		Map<String, byte[]> dataMap = new HashMap<>();
		dataMap.put("sample", "sample".getBytes());
		dataMap.put("null", null);
		dataMap.put("empty-array", new byte[] {});
		dataMap.put("0", new byte[] { 0 });
		dataMap.put("1.2.3.4.5", new byte[] { 1, 2, 3, 4, 5 });
		MemoryDataLoader memoryDataLoader = new MemoryDataLoader(dataMap);
		
		FileCacheDataLoader offlineFileCacheDataLoader = new FileCacheDataLoader();
		offlineFileCacheDataLoader.setCacheExpirationTime(Long.MAX_VALUE);
		offlineFileCacheDataLoader.setDataLoader(new IgnoreDataLoader());
		offlineFileCacheDataLoader.setFileCacheDirectory(cacheDirectory);
		
		List<String> urls = Arrays.asList("sample", "null", "empty-array", "0", "1.2.3.4.5");
		DSSException multipleException = assertThrows(DSSException.class, () -> offlineFileCacheDataLoader.get(urls));
		assertTrue(multipleException.getMessage().contains("sample"));
		assertTrue(multipleException.getMessage().contains("null"));
		assertTrue(multipleException.getMessage().contains("empty-array"));
		assertTrue(multipleException.getMessage().contains("0"));
		assertTrue(multipleException.getMessage().contains("1.2.3.4.5"));
		
		assertThrows(DSSException.class, () -> offlineFileCacheDataLoader.get("sample"));
		assertThrows(DSSException.class, () -> offlineFileCacheDataLoader.get("null"));
		assertThrows(DSSException.class, () -> offlineFileCacheDataLoader.get("empty-array"));
		assertThrows(DSSException.class, () -> offlineFileCacheDataLoader.get("0"));
		assertThrows(DSSException.class, () -> offlineFileCacheDataLoader.get("1.2.3.4.5"));
		
		FileCacheDataLoader onlineFileCacheDataLoader = new FileCacheDataLoader();
		onlineFileCacheDataLoader.setCacheExpirationTime(0);
		onlineFileCacheDataLoader.setDataLoader(memoryDataLoader);
		onlineFileCacheDataLoader.setFileCacheDirectory(cacheDirectory);
		
		assertNotNull(onlineFileCacheDataLoader.get("sample"));
		assertThrows(DSSException.class, () -> onlineFileCacheDataLoader.get("null"));
		assertThrows(DSSException.class, () -> onlineFileCacheDataLoader.get("empty-array"));
		assertNotNull(onlineFileCacheDataLoader.get("0"));
		assertNotNull(onlineFileCacheDataLoader.get("1.2.3.4.5"));
		
		assertNotNull(offlineFileCacheDataLoader.get("sample"));
		assertThrows(DSSException.class, () -> offlineFileCacheDataLoader.get("null"));
		assertThrows(DSSException.class, () -> offlineFileCacheDataLoader.get("empty-array"));
		assertNotNull(offlineFileCacheDataLoader.get("0"));
		assertNotNull(offlineFileCacheDataLoader.get("1.2.3.4.5"));
		
		DataAndUrl dataAndUrl = offlineFileCacheDataLoader.get(Arrays.asList("sample", "null", "empty-array", "0", "1.2.3.4.5"));
		assertNotNull(dataAndUrl);
		assertEquals("sample", dataAndUrl.getUrlString());
		assertNotNull(dataAndUrl.getData());
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

	private void waitOneSecond() {
		Calendar nextSecond = Calendar.getInstance();
		nextSecond.add(Calendar.SECOND, 1);
		await().atMost(2, TimeUnit.SECONDS).until(() -> Calendar.getInstance().getTime().compareTo(nextSecond.getTime()) > 0);
	}
}
