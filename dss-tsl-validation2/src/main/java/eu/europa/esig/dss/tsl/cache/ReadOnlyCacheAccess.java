package eu.europa.esig.dss.tsl.cache;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.parsing.LOTLParsingResult;
import eu.europa.esig.dss.tsl.parsing.TLParsingResult;
import eu.europa.esig.dss.tsl.validation.ValidationResult;

public class ReadOnlyCacheAccess {

	private static final Logger LOG = LoggerFactory.getLogger(ReadOnlyCacheAccess.class);

	/* Global Cache */
	private final DownloadCache fileCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;

	public ReadOnlyCacheAccess(final DownloadCache fileCache, final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.fileCache = fileCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}

	public XmlDownloadResult getDownloadResult(CacheKey key) {
		XmlDownloadResult cachedResult = fileCache.get(key).getCachedResult();
		if (cachedResult != null) {
			return new XmlDownloadResult(cachedResult);
		}
		LOG.debug("The download cached result for a key [{}] does not exist! Return null.", key);
		return null;
	}

	public AbstractParsingResult getParsingResult(CacheKey key) {
		AbstractParsingResult cachedResult = parsingCache.get(key).getCachedResult();
		if (cachedResult != null) {
			if (cachedResult instanceof TLParsingResult) {
				return new TLParsingResult((TLParsingResult) cachedResult);
			} else if (cachedResult instanceof LOTLParsingResult) {
				return new LOTLParsingResult((LOTLParsingResult) cachedResult);
			}
			throw new DSSException("Unsupported ParsingResult type obtained!");
		}
		LOG.debug("The parsing cached result for a key [{}] does not exist! Return null.", key);
		return null;
	}
	
	public Map<CacheKey, AbstractParsingResult> getParsingResultMap(List<CacheKey> keys) {
		return keys.stream().collect(Collectors.toMap(key -> key, key -> getParsingResult(key)));
	}

	public ValidationResult getValidationResult(CacheKey key) {
		ValidationResult cachedResult = validationCache.get(key).getCachedResult();
		if (cachedResult != null) {
			return new ValidationResult(cachedResult);
		}
		LOG.debug("The validation cached result for a key [{}] does not exist! Return null.", key);
		return null;
	}

}
