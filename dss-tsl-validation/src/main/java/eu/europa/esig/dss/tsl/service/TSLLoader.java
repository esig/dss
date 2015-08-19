package eu.europa.esig.dss.tsl.service;

import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.tsl.TSLLoaderResult;

public class TSLLoader implements Callable<TSLLoaderResult> {

	private static final Logger logger = LoggerFactory.getLogger(TSLLoader.class);

	private DataLoader dataLoader;
	private String countryCode;
	private String urlToLoad;

	public TSLLoader(DataLoader dataLoader, String countryCode, String urlToLoad) {
		this.dataLoader = dataLoader;
		this.countryCode= countryCode;
		this.urlToLoad = urlToLoad;
	}

	@Override
	public TSLLoaderResult call() throws Exception {
		TSLLoaderResult result = new TSLLoaderResult();
		result.setCountryCode(countryCode);
		result.setUrl(urlToLoad);
		try {
			byte[] byteArray = dataLoader.get(urlToLoad);
			result.setContent(byteArray);
		} catch (Exception e) {
			logger.warn("Unable to load '" + urlToLoad + "' : " + e.getMessage());
		}

		return result;
	}

}
