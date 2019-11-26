package eu.europa.esig.dss.tsl.cache.state;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingResult;
import eu.europa.esig.dss.tsl.parsing.TLParsingResult;
import eu.europa.esig.dss.tsl.validation.ValidationResult;

public class CacheCleanerTest {
	
	private CacheCleaner cacheCleaner;
	private FileCacheDataLoader fileLoader;
	
	private DownloadCache downloadCache;
	private ParsingCache parsingCache;
	private ValidationCache validationCache;
	
	@TempDir
	File cacheDirectory;
	
	private static final String SAMPLE_FILE_NAME = "sample";
	private static final String LOTL_FILE_NAME = "eu-lotl";
	
	@BeforeEach
	public void init() {
		
		DSSDocument sampleDocument = new InMemoryDocument(SAMPLE_FILE_NAME.getBytes());
		DSSDocument lotlDocument = new InMemoryDocument(LOTL_FILE_NAME.getBytes());
		
		Map<String, byte[]> dataMap = new HashMap<String, byte[]>();
		dataMap.put(SAMPLE_FILE_NAME, SAMPLE_FILE_NAME.getBytes());
		dataMap.put(LOTL_FILE_NAME, LOTL_FILE_NAME.getBytes());
		MemoryDataLoader memoryDataLoader = new MemoryDataLoader(dataMap);
		
		fileLoader = new FileCacheDataLoader();
		fileLoader.setCacheExpirationTime(0);
		fileLoader.setDataLoader(memoryDataLoader);
		fileLoader.setFileCacheDirectory(cacheDirectory);
		
		byte[] sampleContent = fileLoader.get(SAMPLE_FILE_NAME);
		assertTrue(Arrays.equals(SAMPLE_FILE_NAME.getBytes(), sampleContent));
		byte[] lotlContent = fileLoader.get(LOTL_FILE_NAME);
		assertTrue(Arrays.equals(LOTL_FILE_NAME.getBytes(), lotlContent));
		
		cacheCleaner = new CacheCleaner();
		
		downloadCache = new DownloadCache();
		downloadCache.update(new CacheKey(SAMPLE_FILE_NAME), new XmlDownloadResult(sampleDocument, 
				new Digest(DigestAlgorithm.SHA1, DSSUtils.digest(DigestAlgorithm.SHA1, sampleDocument))));
		downloadCache.update(new CacheKey(LOTL_FILE_NAME), new XmlDownloadResult(lotlDocument, 
				new Digest(DigestAlgorithm.SHA1, DSSUtils.digest(DigestAlgorithm.SHA1, lotlDocument))));
		
		parsingCache = new ParsingCache();
		parsingCache.update(new CacheKey(SAMPLE_FILE_NAME), new TLParsingResult());
		parsingCache.update(new CacheKey(LOTL_FILE_NAME), new LOTLParsingResult());
		
		validationCache = new ValidationCache();
		validationCache.update(new CacheKey(SAMPLE_FILE_NAME), new ValidationResult(Indication.PASSED, null, new Date(), null, null));
		validationCache.update(new CacheKey(LOTL_FILE_NAME), new ValidationResult(Indication.PASSED, null, new Date(), null, null));
	}
	
	@Test
	public void test() {
		cacheCleaner.setDSSFileLoader(fileLoader);
		cacheCleaner.setCleanFileSystem(true);
		
		File sampleFile = new File(cacheDirectory, DSSUtils.getNormalizedString(SAMPLE_FILE_NAME));
		File lotlFile = new File(cacheDirectory, DSSUtils.getNormalizedString(LOTL_FILE_NAME));
		
		assertTrue(sampleFile.exists());
		assertTrue(lotlFile.exists());
		
		CacheKey sampleCacheKey = new CacheKey(SAMPLE_FILE_NAME);
		CacheKey lotlCacheKey = new CacheKey(LOTL_FILE_NAME);
		
		validateEntries(sampleCacheKey, false, false);
		validateEntries(lotlCacheKey, false, false);
		
		downloadCache.sync(sampleCacheKey);
		parsingCache.sync(sampleCacheKey);
		validationCache.sync(sampleCacheKey);
		
		validateEntries(sampleCacheKey, false, false);
		validateEntries(lotlCacheKey, false, false);
		
		CacheAccessByKey cacheAccessByKey = new CacheAccessByKey(new CacheKey(SAMPLE_FILE_NAME), downloadCache, parsingCache, validationCache);
		cacheCleaner.clean(cacheAccessByKey);

		// need TO_BE_DELETED to be set
		validateEntries(sampleCacheKey, false, false);
		validateEntries(lotlCacheKey, false, false);
		
		downloadCache.toBeDeleted(sampleCacheKey);
		parsingCache.toBeDeleted(sampleCacheKey);
		validationCache.toBeDeleted(sampleCacheKey);
		
		assertTrue(downloadCache.isToBeDeleted(sampleCacheKey));
		assertTrue(parsingCache.isToBeDeleted(sampleCacheKey));
		assertTrue(validationCache.isToBeDeleted(sampleCacheKey));
		assertFalse(downloadCache.isToBeDeleted(lotlCacheKey));
		assertFalse(parsingCache.isToBeDeleted(lotlCacheKey));
		assertFalse(validationCache.isToBeDeleted(lotlCacheKey));
		
		// the clean operation is still not processed
		validateEntries(sampleCacheKey, false, false);
		validateEntries(lotlCacheKey, false, false);
		
		assertTrue(sampleFile.exists());
		assertTrue(lotlFile.exists());
		
		cacheCleaner.clean(cacheAccessByKey);
		
		validateEntries(sampleCacheKey, true, true);
		validateEntries(lotlCacheKey, false, false);
		
		assertFalse(sampleFile.exists());
		assertTrue(lotlFile.exists());
		
		downloadCache.sync(lotlCacheKey);
		parsingCache.sync(lotlCacheKey);
		validationCache.sync(lotlCacheKey);
		
		downloadCache.toBeDeleted(lotlCacheKey);
		parsingCache.toBeDeleted(lotlCacheKey);
		validationCache.toBeDeleted(lotlCacheKey);
		
		assertFalse(downloadCache.isToBeDeleted(sampleCacheKey));
		assertFalse(parsingCache.isToBeDeleted(sampleCacheKey));
		assertFalse(validationCache.isToBeDeleted(sampleCacheKey));
		assertTrue(downloadCache.isToBeDeleted(lotlCacheKey));
		assertTrue(parsingCache.isToBeDeleted(lotlCacheKey));
		assertTrue(validationCache.isToBeDeleted(lotlCacheKey));
		
		assertFalse(sampleFile.exists());
		assertTrue(lotlFile.exists());

		cacheAccessByKey = new CacheAccessByKey(new CacheKey(LOTL_FILE_NAME), downloadCache, parsingCache, validationCache);
		cacheCleaner.clean(cacheAccessByKey);
		
		validateEntries(sampleCacheKey, true, true);
		validateEntries(lotlCacheKey, true, true);
		
		assertFalse(sampleFile.exists());
		assertFalse(lotlFile.exists());
	}
	
	@Test
	public void cacheCleanerNoDeleteTest() {
		cacheCleaner.setDSSFileLoader(fileLoader);
		cacheCleaner.setCleanMemory(false);
		cacheCleaner.setCleanFileSystem(false);
		
		File sampleFile = new File(cacheDirectory, DSSUtils.getNormalizedString(SAMPLE_FILE_NAME));
		File lotlFile = new File(cacheDirectory, DSSUtils.getNormalizedString(LOTL_FILE_NAME));
		
		assertTrue(sampleFile.exists());
		assertTrue(lotlFile.exists());
		
		CacheKey sampleCacheKey = new CacheKey(SAMPLE_FILE_NAME);
		CacheKey lotlCacheKey = new CacheKey(LOTL_FILE_NAME);
		
		validateEntries(sampleCacheKey, false, false);
		validateEntries(lotlCacheKey, false, false);
		
		downloadCache.sync(sampleCacheKey);
		validationCache.sync(sampleCacheKey);
		downloadCache.sync(lotlCacheKey);
		parsingCache.sync(lotlCacheKey);

		downloadCache.toBeDeleted(sampleCacheKey);
		validationCache.toBeDeleted(sampleCacheKey);
		downloadCache.toBeDeleted(lotlCacheKey);
		parsingCache.toBeDeleted(lotlCacheKey);
		
		assertTrue(downloadCache.isToBeDeleted(sampleCacheKey));
		assertFalse(parsingCache.isToBeDeleted(sampleCacheKey));
		assertTrue(validationCache.isToBeDeleted(sampleCacheKey));
		assertTrue(downloadCache.isToBeDeleted(lotlCacheKey));
		assertTrue(parsingCache.isToBeDeleted(lotlCacheKey));
		assertFalse(validationCache.isToBeDeleted(lotlCacheKey));

		CacheAccessByKey cacheAccessByKey = new CacheAccessByKey(new CacheKey(SAMPLE_FILE_NAME), downloadCache, parsingCache, validationCache);
		cacheCleaner.clean(cacheAccessByKey);
		cacheAccessByKey = new CacheAccessByKey(new CacheKey(LOTL_FILE_NAME), downloadCache, parsingCache, validationCache);
		cacheCleaner.clean(cacheAccessByKey);
		
		validateEntries(sampleCacheKey, false, false);
		validateEntries(lotlCacheKey, false, false);
		
		assertTrue(downloadCache.isToBeDeleted(sampleCacheKey));
		assertFalse(parsingCache.isToBeDeleted(sampleCacheKey));
		assertTrue(validationCache.isToBeDeleted(sampleCacheKey));
		assertTrue(downloadCache.isToBeDeleted(lotlCacheKey));
		assertTrue(parsingCache.isToBeDeleted(lotlCacheKey));
		assertFalse(validationCache.isToBeDeleted(lotlCacheKey));
		
		assertTrue(sampleFile.exists());
		assertTrue(lotlFile.exists());
	}
	
	@Test
	public void noFileLoaderDefinedTest() {
		CacheAccessByKey cacheAccessByKey = new CacheAccessByKey(new CacheKey(SAMPLE_FILE_NAME), downloadCache, parsingCache, validationCache);
		cacheCleaner.clean(cacheAccessByKey);
		
		cacheCleaner.setCleanFileSystem(true);
		assertThrows(NullPointerException.class, () -> cacheCleaner.clean(cacheAccessByKey));
	}
	
	private void validateEntries(final CacheKey cacheKey, final boolean isEmpty, final boolean isRefreshNeeded) {
		assertEquals(isEmpty, downloadCache.isEmpty(cacheKey));
		assertEquals(isRefreshNeeded, downloadCache.isRefreshNeeded(cacheKey));
		
		assertEquals(isEmpty, parsingCache.isEmpty(cacheKey));
		assertEquals(isRefreshNeeded, parsingCache.isRefreshNeeded(cacheKey));
		
		assertEquals(isEmpty, validationCache.isEmpty(cacheKey));
		assertEquals(isRefreshNeeded, validationCache.isRefreshNeeded(cacheKey));
	}
	
}
