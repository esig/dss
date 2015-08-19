package eu.europa.esig.dss.tsl.service;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.tsl.TSLLoaderResult;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLPointer;
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

	public void refresh() {

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
				repository.updateParseResult(tslParserResult);
			} catch (Exception e) {
				logger.error("Unable to get parsing result : " + e.getMessage(), e);
			}
		}

		for (Future<TSLValidationResult> futureValidationResult : futureValidationResults) {
			try {
				TSLValidationResult tslValidationResult = futureValidationResult.get();
				repository.updateValidationResult(tslValidationResult);
			} catch (Exception e) {
				logger.error("Unable to get validation result : " + e.getMessage(), e);
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
