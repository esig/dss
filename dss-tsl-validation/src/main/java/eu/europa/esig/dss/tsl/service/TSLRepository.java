package eu.europa.esig.dss.tsl.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
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

	private boolean allowExpiredTSLs = false;

	private boolean allowInvalidSignatures = false;

	private Map<String, TSLValidationModel> tsls = new HashMap<String, TSLValidationModel>();

	public void setCacheDirectoryPath(String cacheDirectoryPath) {
		this.cacheDirectoryPath = cacheDirectoryPath;
	}

	public void setAllowExpiredTSLs(boolean allowExpiredTSLs) {
		this.allowExpiredTSLs = allowExpiredTSLs;
	}

	public void setAllowInvalidSignatures(boolean allowInvalidSignatures) {
		this.allowInvalidSignatures = allowInvalidSignatures;
	}

	public TSLValidationModel getByCountry(String countryIsoCode) {
		return tsls.get(countryIsoCode);
	}

	public List<TSLValidationModel> getTSLValidationModels() {
		List<TSLValidationModel> result = new ArrayList<TSLValidationModel>();
		Date now = new Date();
		for (TSLValidationModel tslValidationModel : tsls.values()) {
			if (!allowExpiredTSLs) {
				TSLParserResult parseResult = tslValidationModel.getParseResult();
				if (parseResult != null) {
					if (now.after(parseResult.getNextUpdateDate())) {
						continue;
					}
				}
			}
			if (!allowInvalidSignatures) {
				TSLValidationResult validationResult = tslValidationModel.getValidationResult();
				if (validationResult != null) {
					if (!validationResult.isSignatureValid()) {
						continue;
					}
				}
			}
			result.add(tslValidationModel);
		}
		return Collections.unmodifiableList(result);
	}

	public Map<String, TSLValidationModel> getAllMapTSLValidationModels() {
		return Collections.unmodifiableMap(tsls);
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
			// TODO Best place ? Download didn't work, we use previous version
			if (ArrayUtils.isEmpty(resultLoader.getContent())){
				return true;
			}
			validationModel.setUrl(resultLoader.getUrl());
			validationModel.setLoadedDate(new Date());
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
		validationModel.setUrl(resultLoader.getUrl());
		validationModel.setSha256FileContent(getSHA256(resultLoader.getContent()));
		validationModel.setFilepath(storeOnFileSystem(resultLoader.getCountryCode(), resultLoader));
		validationModel.setLoadedDate(new Date());
		add(resultLoader.getCountryCode(), validationModel);
		logger.info("New version of " + resultLoader.getCountryCode() + " TSL is stored in cache");
		return validationModel;
	}

	void addParsedResultFromCacheToMap(TSLParserResult tslParserResult) {
		TSLValidationModel validationModel = new TSLValidationModel();
		String countryCode = tslParserResult.getTerritory();
		String filePath = getFilePath(countryCode);
		validationModel.setFilepath(filePath);
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(filePath);
			byte[] data = IOUtils.toByteArray(fis);
			validationModel.setSha256FileContent(getSHA256(data));
		} catch (Exception e) {
			logger.error("Unable to read '" + filePath + "' : " + e.getMessage());
		} finally {
			IOUtils.closeQuietly(fis);
		}
		validationModel.setParseResult(tslParserResult);
		add(countryCode, validationModel);
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

	List<File> getStoredFiles() {
		ensureCacheDirectoryExists();
		File cacheDir = new File(cacheDirectoryPath);
		File[] listFiles = cacheDir.listFiles();
		return Arrays.asList(listFiles);
	}

	public boolean isOk() {
		List<TSLValidationModel> filteredList = getTSLValidationModels();
		Map<String, TSLValidationModel> allData = getAllMapTSLValidationModels();
		return filteredList.size() == allData.size();
	}

}
