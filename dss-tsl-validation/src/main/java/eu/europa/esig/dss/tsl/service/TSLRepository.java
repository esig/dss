package eu.europa.esig.dss.tsl.service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.tsl.TSLLoaderResult;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.TSLValidationResult;

public class TSLRepository {

	private static final Logger logger = LoggerFactory.getLogger(TSLRepository.class);

	private String cacheDirectoryPath = System.getProperty("java.io.tmpdir") + File.separator + "dss-cache-tsl" + File.separator;

	private Map<String, TSLValidationModel> tsls = new HashMap<String, TSLValidationModel>();

	/*
	@PostConstruct
	public void initRepository() {
		logger.info("Initialization of the TSL repository ...");
		int loadedTSL = 0;
		File cacheDir = new File(cacheDirectoryPath);
		if (cacheDir.exists() && cacheDir.isDirectory()) {
			File[] listFiles = cacheDir.listFiles();
			if (ArrayUtils.isNotEmpty(listFiles)) {
				for (File file : listFiles) {
					FileInputStream fis = null;
					try {
						fis = new FileInputStream(file);
						byte[] byteArray = IOUtils.toByteArray(fis);
						TSLValidationModel validationModel = parser.parseTSL(fis);
						validationModel.setFilepath(file.getAbsolutePath());
						validationModel.setSha256FileContent(getSHA256(byteArray));
						add(validationModel);
						loadedTSL++;
					} catch (Exception e) {
						logger.error("Cannot parse file '" + file.getAbsolutePath() + "' : " + e.getMessage(), e);
					} finally {
						IOUtils.closeQuietly(fis);
					}
				}
			}
		} else {
			cacheDir.mkdirs();
		}
		logger.info(loadedTSL + " loaded TSL from cached files in the repository");
	}*/

	public void setCacheDirectoryPath(String cacheDirectoryPath) {
		this.cacheDirectoryPath = cacheDirectoryPath;
	}

	public TSLValidationModel getByCountry(String countryIsoCode) {
		return tsls.get(countryIsoCode);
	}

	public void clearRepository() {
		try {
			FileUtils.cleanDirectory(new File(cacheDirectoryPath));
			tsls.clear();
		} catch (IOException e) {
			logger.error("Unable to clean cache directory : " + e.getMessage(), e);
		}
	}

	boolean isLastVersion(TSLLoaderResult resultLoader) {
		TSLValidationModel validationModel = getByCountry(resultLoader.getCountryCode());
		if (validationModel == null) {
			return false;
		} else {
			String lastSha256 = getSHA256(resultLoader.getContent());
			return StringUtils.equals(lastSha256, validationModel.getSha256FileContent());
		}
	}

	void updateParseResult(TSLParserResult tslParserResult) {
		TSLValidationModel validationModel = getByCountry(tslParserResult.getTerritory());
		if (validationModel != null) {
			validationModel.setParseResult(tslParserResult);
		}
	}

	void updateValidationResult(TSLValidationResult tslValidationResult) {
		TSLValidationModel validationModel = getByCountry(tslValidationResult.getCountryCode());
		if (validationModel != null) {
			validationModel.setValidationResult(tslValidationResult);
		}
	}

	TSLValidationModel storeInCache(TSLLoaderResult resultLoader) {
		TSLValidationModel validationModel = new TSLValidationModel();
		String filePath = storeOnFileSystem(resultLoader.getCountryCode(), resultLoader);
		validationModel.setFilepath(filePath);
		validationModel.setUrl(resultLoader.getUrl());
		validationModel.setSha256FileContent(getSHA256(resultLoader.getContent()));
		add(resultLoader.getCountryCode(), validationModel);
		return validationModel;
	}

	private void add(String countryCode, TSLValidationModel tsl) {
		tsls.put(countryCode, tsl);
	}

	private String storeOnFileSystem(String countryCode, TSLLoaderResult resultLoader) {
		ensureCacheDirectoryExists();
		String filePath = getFilePath(countryCode);
		File fileToCreate = new File(filePath);
		OutputStream os = null;
		try {
			os = new FileOutputStream(fileToCreate);
			IOUtils.write(resultLoader.getContent(), os);
		} catch (Exception e) {
			throw new DSSException("Cannot create file in cache : " + e.getMessage(), e);
		} finally {
			IOUtils.closeQuietly(os);
		}
		return filePath;
	}

	private void ensureCacheDirectoryExists() {
		File cacheDir = new File(cacheDirectoryPath);
		if (!cacheDir.exists() || !cacheDir.isDirectory()) {
			cacheDir.mkdirs();
		}
	}

	private String getFilePath(String countryCode) {
		return cacheDirectoryPath + countryCode + ".xml";
	}

	private String getSHA256(byte[] data) {
		return DatatypeConverter.printBase64Binary(DSSUtils.digest(DigestAlgorithm.SHA256, data));
	}

}
