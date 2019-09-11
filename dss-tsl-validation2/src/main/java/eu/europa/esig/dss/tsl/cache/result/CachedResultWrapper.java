package eu.europa.esig.dss.tsl.cache.result;

import java.util.Date;

/**
 * Contains the {@code Result} and its relevant information
 *
 * @param <R> implementation of {@link CachedResult} interface
 */
public class CachedResultWrapper<R extends CachedResult> {
	
	/**
	 * The cached result
	 */
	private final R result;
	
	/**
	 * Date of the last update for the current cached result
	 */
	private final Date updateDate;
	
	/**
	 * The default CacheWrapper constructor
	 * @param result {@link CachedResult}
	 */
	public CachedResultWrapper(R result) {
		this.result = result;
		this.updateDate = new Date(); // store the current date on instantiation
	}
	
	/**
	 * Returns the {@code Result}
	 * @return {@link CachedResult}
	 */
	public R getResult() {
		return result;
	}
	
	/**
	 * Returns the update date of the cached result
	 * @return {@link Date}
	 */
	public Date getUpdateDate() {
		return updateDate;
	}

}
