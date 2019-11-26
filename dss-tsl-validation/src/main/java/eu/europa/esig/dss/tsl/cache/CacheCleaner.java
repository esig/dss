package eu.europa.esig.dss.tsl.cache;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;

/**
 * The class is used to clean outdated cache entries
 */
public class CacheCleaner {

	private static final Logger LOG = LoggerFactory.getLogger(CacheCleaner.class);
	
	/**
	 * If true, removes all map entries with status TO_BE_DELETED
	 * Default : true
	 */
	private boolean cleanMemory = true;
	
	/**
	 * If true, removes files from the file system for each entry with status TO_BE_DELETED
	 * Default : false
	 */
	private boolean cleanFileSystem = false;
	
	/**
	 * The {@code DSSFileLoader} used to remove files from the File System
	 */
	private DSSFileLoader dssFileLoader;
	
	/**
	 * Setter for cleanMemory property
	 * 
	 * @param cleanMemory
	 *                    if TRUE, removes TO_BE_DELETED entries from in memory maps
	 */
	public void setCleanMemory(final boolean cleanMemory) {
		this.cleanMemory = cleanMemory;
	}
	
	/**
	 * Setter for cleanFileSystem property
	 * 
	 * @param cleanFileSystem
	 *                        if TRUE, removes TO_BE_DELETED entries from file
	 *                        system
	 */
	public void setCleanFileSystem(final boolean cleanFileSystem) {
		this.cleanFileSystem = cleanFileSystem;
	}
	
	/**
	 * Sets the DSSFileLoader that will be used for file removing
	 * @param dssFileLoader {@link DSSFileLoader}
	 */
	public void setDSSFileLoader(final DSSFileLoader dssFileLoader) {
		this.dssFileLoader = dssFileLoader;
	}
	
	/**
	 * Cleans the given entry
	 * @param cacheAccess {@link CacheAccessByKey}
	 */
	public void clean(CacheAccessByKey cacheAccess) {
		
		LOG.trace("Starting the clean operation for the entry with the key [{}]", cacheAccess.getCacheKey());
		boolean fileNeedToBeDeleted = cacheAccess.isFileNeedToBeDeleted();
		if (cleanMemory) {
			LOG.trace("cleanMemory is running for the entry with the key [{}]", cacheAccess.getCacheKey());
			cacheAccess.deleteDownloadCacheIfNeeded();
			cacheAccess.deleteParsingCacheIfNeeded();
			cacheAccess.deleteValidationCacheIfNeeded();
		}
		
		if (cleanFileSystem) {
			Objects.requireNonNull(dssFileLoader, "Cannot remove files from the file system. The DSSFileLoader must be defined!");
			
			if (fileNeedToBeDeleted) {
				LOG.trace("cleanFileSystem is running for the entry with the key [{}]", cacheAccess.getCacheKey());
				try {
					boolean removed = dssFileLoader.remove(cacheAccess.getCacheKey().getKey());
					if (removed) {
						LOG.info("The file with cacheKey [{}] has been successfully removed from the file system", 
								cacheAccess.getCacheKey());
					} else {
						LOG.warn("The file with cacheKey [{}] was not removed from the file system", 
								cacheAccess.getCacheKey());
					}
					
				} catch (Exception e) {
					LOG.warn("An error occurred on removing of file with cacheKey [{}] from file system. Reason : {}", 
							cacheAccess.getCacheKey(), e.getMessage());
				}
			}
			
		}
	}

}
