package eu.europa.esig.dss.tsl.service;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.annotation.PostConstruct;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.tsl.TSLLoaderResult;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.TSLValidationResult;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class TSLValidationJob {

	private static final String EUROPA_COUNTRY_CODE = "EU";

	private static final Logger logger = LoggerFactory.getLogger(TSLValidationJob.class);

	private ExecutorService executorService = Executors.newCachedThreadPool();

	private DataLoader dataLoader;
	private TSLRepository repository;
	private String lotlUrl;
	private KeyStoreCertificateSource dssKeyStore;
	private boolean checkLOTLSignature = true;
	private boolean checkTSLSignatures = true;
	private List<String> filterTerritories;

	public void setExecutorService(ExecutorService executorService) {
		this.executorService = executorService;
	}

	public void setDataLoader(DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	public void setRepository(TSLRepository repository) {
		this.repository = repository;
	}

	public void setLotlUrl(String lotlUrl) {
		this.lotlUrl = lotlUrl;
	}

	public void setDssKeyStore(KeyStoreCertificateSource dssKeyStore) {
		this.dssKeyStore = dssKeyStore;
	}

	public void setCheckLOTLSignature(boolean checkLOTLSignature) {
		this.checkLOTLSignature = checkLOTLSignature;
	}

	public void setCheckTSLSignatures(boolean checkTSLSignatures) {
		this.checkTSLSignatures = checkTSLSignatures;
	}

	public void setFilterTerritories(List<String> filterTerritories) {
		this.filterTerritories = filterTerritories;
	}

	@PostConstruct
	public void initRepository() {
		logger.info("Initialization of the TSL repository ...");
		int loadedTSL = 0;
		List<File> cachedFiles = repository.getStoredFiles();
		if (CollectionUtils.isNotEmpty(cachedFiles)) {
			List<Future<TSLParserResult>> futureParseResults = new ArrayList<Future<TSLParserResult>>();
			for (File file : cachedFiles) {
				try {
					FileInputStream fis = new FileInputStream(file);
					futureParseResults.add(executorService.submit(new TSLParser(fis)));
				} catch (Exception e) {
					logger.error("Unable to parse file '" + file.getAbsolutePath() + "' : " + e.getMessage(), e);
				}
			}

			for (Future<TSLParserResult> futureParseResult : futureParseResults) {
				try {
					TSLParserResult tslParserResult = futureParseResult.get();
					loadMissingCertificates(tslParserResult);
					repository.addParsedResultFromCacheToMap(tslParserResult);
					loadedTSL++;
				} catch (Exception e) {
					logger.error("Unable to get parsing result : " + e.getMessage(), e);
				}
			}

			TSLValidationModel europeanModel = repository.getByCountry(EUROPA_COUNTRY_CODE);
			if (checkLOTLSignature && (europeanModel != null)) {
				try {
					TSLValidationResult europeanValidationResult = validateLOTL(europeanModel);
					europeanModel.setValidationResult(europeanValidationResult);
				} catch (Exception e) {
					logger.error("Unable to validate the LOTL : " + e.getMessage(), e);
				}
			}

			if (checkTSLSignatures && ((europeanModel != null) && (europeanModel.getParseResult() != null))) {
				List<TSLPointer> pointers = europeanModel.getParseResult().getPointers();
				List<Future<TSLValidationResult>> futureValidationResults = new ArrayList<Future<TSLValidationResult>>();
				Map<String, TSLValidationModel> map = repository.getAllMapTSLValidationModels();
				for (Entry<String, TSLValidationModel> entry : map.entrySet()) {
					String countryCode = entry.getKey();
					if (!EUROPA_COUNTRY_CODE.equals(countryCode)) {
						TSLValidationModel countryModel = entry.getValue();
						TSLValidator tslValidator = new TSLValidator(new File(countryModel.getFilepath()), countryCode, dssKeyStore, getPotentialSigners(pointers,
								countryCode));
						futureValidationResults.add(executorService.submit(tslValidator));
					}
				}

				storeValidationResults(futureValidationResults);
			}

			repository.synchronize();
		}
		logger.info(loadedTSL + " loaded TSL from cached files in the repository");
	}

	public void refresh() {
		logger.debug("TSL Validation Job is starting ...");
		TSLLoaderResult resultLoaderLOTL = null;
		Future<TSLLoaderResult> result = executorService.submit(new TSLLoader(dataLoader, EUROPA_COUNTRY_CODE, lotlUrl));
		try {
			resultLoaderLOTL = result.get();
		} catch (Exception e) {
			logger.error("Unable to load the LOTL : " + e.getMessage(), e);
			return;
		}

		TSLValidationModel europeanModel = null;
		if (!repository.isLastVersion(resultLoaderLOTL)) {
			europeanModel = repository.storeInCache(resultLoaderLOTL);
		} else {
			europeanModel = repository.getByCountry(resultLoaderLOTL.getCountryCode());
		}

		TSLParserResult parseResult = europeanModel.getParseResult();
		if (parseResult == null) {
			try {
				parseResult = parseLOTL(europeanModel);
				europeanModel.setParseResult(parseResult);
			} catch (Exception e) {
				logger.error("Unable to parse the LOTL : " + e.getMessage(), e);
				return;
			}
		}

		if (checkLOTLSignature && (europeanModel.getValidationResult() == null)) {
			try {
				TSLValidationResult validationResult = validateLOTL(europeanModel);
				europeanModel.setValidationResult(validationResult);
			} catch (Exception e) {
				logger.error("Unable to validate the LOTL : " + e.getMessage(), e);
			}
		}

		analyzeCountryPointers(parseResult.getPointers());

		repository.synchronize();

		logger.debug("TSL Validation Job is finishing ...");
	}

	private void analyzeCountryPointers(List<TSLPointer> pointers) {
		List<Future<TSLLoaderResult>> futureLoaderResults = new ArrayList<Future<TSLLoaderResult>>();
		for (TSLPointer tslPointer : pointers) {
			if (CollectionUtils.isEmpty(filterTerritories) || filterTerritories.contains(tslPointer.getTerritory())) {
				TSLLoader tslLoader = new TSLLoader(dataLoader, tslPointer.getTerritory(), tslPointer.getUrl());
				futureLoaderResults.add(executorService.submit(tslLoader));
			}
		}

		List<Future<TSLParserResult>> futureParseResults = new ArrayList<Future<TSLParserResult>>();
		List<Future<TSLValidationResult>> futureValidationResults = new ArrayList<Future<TSLValidationResult>>();
		for (Future<TSLLoaderResult> futureLoaderResult : futureLoaderResults) {
			try {
				TSLLoaderResult loaderResult = futureLoaderResult.get();
				TSLValidationModel countryModel = null;
				if (!repository.isLastVersion(loaderResult)) {
					countryModel = repository.storeInCache(loaderResult);
				} else {
					countryModel = repository.getByCountry(loaderResult.getCountryCode());
				}

				TSLParserResult countryParseResult = countryModel.getParseResult();
				if (countryParseResult == null) {
					FileInputStream fis = new FileInputStream(countryModel.getFilepath());
					futureParseResults.add(executorService.submit(new TSLParser(fis)));
				}

				if (checkTSLSignatures && (countryModel.getValidationResult() == null)) {
					TSLValidator tslValidator = new TSLValidator(new File(countryModel.getFilepath()), loaderResult.getCountryCode(), dssKeyStore, getPotentialSigners(pointers,
							loaderResult.getCountryCode()));
					futureValidationResults.add(executorService.submit(tslValidator));
				}
			} catch (Exception e) {
				logger.error("Unable to load/parse TSL : " + e.getMessage(), e);
			}
		}

		for (Future<TSLParserResult> futureParseResult : futureParseResults) {
			try {
				TSLParserResult tslParserResult = futureParseResult.get();
				loadMissingCertificates(tslParserResult);
				repository.updateParseResult(tslParserResult);
			} catch (Exception e) {
				logger.error("Unable to get parsing result : " + e.getMessage(), e);
			}
		}

		storeValidationResults(futureValidationResults);
	}

	private void storeValidationResults(List<Future<TSLValidationResult>> futureValidationResults) {
		for (Future<TSLValidationResult> futureValidationResult : futureValidationResults) {
			try {
				TSLValidationResult tslValidationResult = futureValidationResult.get();
				repository.updateValidationResult(tslValidationResult);
			} catch (Exception e) {
				logger.error("Unable to get validation result : " + e.getMessage(), e);
			}
		}
	}

	/**
	 * The spanish TSL contains some urls with certificates to download
	 */
	private void loadMissingCertificates(TSLParserResult tslParserResult) {
		if ("ES".equals(tslParserResult.getTerritory())) {
			List<TSLServiceProvider> serviceProviders = tslParserResult.getServiceProviders();
			if (CollectionUtils.isNotEmpty(serviceProviders)) {
				for (TSLServiceProvider tslServiceProvider : serviceProviders) {
					List<TSLService> services = tslServiceProvider.getServices();
					if (CollectionUtils.isNotEmpty(services)) {
						for (TSLService tslService : services) {
							List<String> certificateUrls = tslService.getCertificateUrls();
							if (CollectionUtils.isNotEmpty(certificateUrls)) {
								for (String url : certificateUrls) {
									try {
										byte[] byteArray = dataLoader.get(url);
										CertificateToken certificate = DSSUtils.loadCertificate(byteArray);
										if (certificate != null) {
											tslService.getCertificates().add(certificate);
										}
									} catch (Exception e) {
										logger.warn("Cannot load certificate from url '" + url + "' : " + e.getMessage());
									}
								}
							}
						}
					}
				}
			}
		}
	}

	private List<CertificateToken> getPotentialSigners(List<TSLPointer> pointers, String countryCode) {
		if (CollectionUtils.isNotEmpty(pointers)) {
			for (TSLPointer tslPointer : pointers) {
				if (StringUtils.equals(countryCode, tslPointer.getTerritory())) {
					return tslPointer.getPotentialSigners();
				}
			}
		}
		return Collections.emptyList();
	}

	private TSLValidationResult validateLOTL(TSLValidationModel validationModel) throws Exception {
		TSLValidator tslValidator = new TSLValidator(new File(validationModel.getFilepath()), EUROPA_COUNTRY_CODE, dssKeyStore);
		Future<TSLValidationResult> future = executorService.submit(tslValidator);
		return future.get();
	}

	private TSLParserResult parseLOTL(TSLValidationModel validationModel) throws Exception {
		FileInputStream fis = new FileInputStream(validationModel.getFilepath());
		Future<TSLParserResult> future = executorService.submit(new TSLParser(fis));
		return future.get();
	}

}
