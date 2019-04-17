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
package eu.europa.esig.dss.tsl.service;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.tsl.OtherTrustedList;
import eu.europa.esig.dss.tsl.TSLLoaderResult;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.TSLValidationResult;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

/**
 * This class is job class which allows to launch TSL loading/parsing/validation. An instance of this class can be
 * injected in a Spring quartz job.
 */
public class TSLValidationJob {

	private static final Logger LOG = LoggerFactory.getLogger(TSLValidationJob.class);

	private ExecutorService executorService = Executors.newCachedThreadPool();

	private DataLoader dataLoader;
	private TSLRepository repository;
	private String lotlCode;
	private String lotlUrl;
	private String lotlRootSchemeInfoUri;

	/*
	 * Official journal Domain Name where the allowed certificates can be found. This URL with this DN is present in the LOTL
	 */
	private String ojDomainName;
	
	private KeyStoreCertificateSource ojContentKeyStore;

	private boolean checkLOTLSignature = true;
	private boolean checkTSLSignatures = true;
	private List<String> filterTerritories;

	private List<OtherTrustedList> otherTrustedLists;

	public void setExecutorService(ExecutorService executorService) {
		if (this.executorService != null && !this.executorService.isShutdown()) {
			this.executorService.shutdownNow();
		}
		this.executorService = executorService;
	}

	public void setDataLoader(DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	public void setRepository(TSLRepository repository) {
		this.repository = repository;
	}

	/**
	 * This method allows to set the LOTL country code
	 * 
	 * @param lotlCode
	 *            the country code (EU in European Union)
	 */
	public void setLotlCode(String lotlCode) {
		this.lotlCode = lotlCode;
	}

	/**
	 * This method allows to set the LOTL URL
	 * 
	 * @param lotlUrl
	 *            the LOTL Url
	 */
	public void setLotlUrl(String lotlUrl) {
		this.lotlUrl = lotlUrl;
	}

	/**
	 * This method allows to set the root URI for the LOTL HTML page (SchemeInformationURI)
	 * 
	 * @param lotlRootSchemeInfoUri
	 */
	public void setLotlRootSchemeInfoUri(String lotlRootSchemeInfoUri) {
		this.lotlRootSchemeInfoUri = lotlRootSchemeInfoUri;
	}

	/**
	 * This method allows to set the Official Journal Domain Name (where the trusted certificates are listed)
	 * 
	 * @param ojUrl
	 *            the Official Journal Domain Name
	 */
	public void setOjDomainName(String ojDomainName) {
		this.ojDomainName = ojDomainName;
	}

	public void setOjContentKeyStore(KeyStoreCertificateSource ojContentKeyStore) {
		this.ojContentKeyStore = ojContentKeyStore;
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

	/**
	 * This parameter allows to add non EU trusted lists.
	 * 
	 * @param otherTrustedLists
	 *            a list of additional trusted lists to be supported
	 */
	public void setOtherTrustedLists(List<OtherTrustedList> otherTrustedLists) {
		this.otherTrustedLists = otherTrustedLists;
	}

	public void initRepository() {
		LOG.info("Initialization of the TSL repository ...");
		int loadedTSL = 0;
		List<File> cachedFiles = repository.getStoredFiles();
		if (Utils.isCollectionNotEmpty(cachedFiles)) {
			List<Future<TSLParserResult>> futureParseResults = new ArrayList<Future<TSLParserResult>>();
			for (File file : cachedFiles) {
				try {
					futureParseResults.add(executorService.submit(new TSLParser(new FileDocument(file))));
				} catch (Exception e) {
					LOG.error("Unable to parse file '" + file.getAbsolutePath() + "' : " + e.getMessage(), e);
				}
			}

			for (Future<TSLParserResult> futureParseResult : futureParseResults) {
				try {
					TSLParserResult tslParserResult = futureParseResult.get();
					repository.addParsedResultFromCacheToMap(tslParserResult);
					loadedTSL++;
				} catch (Exception e) {
					LOG.error("Unable to get parsing result : " + e.getMessage(), e);
				}
			}

			TSLValidationModel europeanModel = repository.getByCountry(lotlCode);
			if (checkLOTLSignature && (europeanModel != null)) {
				try {
					// pivot is not handled in the cache loading
					TSLValidationResult europeanValidationResult = validateLOTL(europeanModel, ojContentKeyStore.getCertificates());
					europeanModel.setValidationResult(europeanValidationResult);
				} catch (Exception e) {
					LOG.error("Unable to validate the LOTL : " + e.getMessage(), e);
				}
			}

			if (checkTSLSignatures && ((europeanModel != null) && (europeanModel.getParseResult() != null))) {
				List<TSLPointer> lotlPointers = europeanModel.getParseResult().getPointers();
				List<Future<TSLValidationResult>> futureValidationResults = new ArrayList<Future<TSLValidationResult>>();
				Map<String, TSLValidationModel> map = repository.getAllMapTSLValidationModels();
				for (Entry<String, TSLValidationModel> entry : map.entrySet()) {
					String countryCode = entry.getKey();

					if (!lotlCode.equals(countryCode)) {
						TSLValidationModel countryModel = entry.getValue();
						OtherTrustedList otherTL = getNonEUTrustedList(countryCode);
						List<CertificateToken> potentialSigners = null;
						if (otherTL != null) {
							potentialSigners = otherTL.getTrustStore().getCertificates();
						} else {
							potentialSigners = getPotentialSigners(lotlPointers, countryCode);
						}
						TSLValidator tslValidator = new TSLValidator(new FileDocument(countryModel.getFilepath()), countryCode, potentialSigners);
						futureValidationResults.add(executorService.submit(tslValidator));
					}
				}

				storeValidationResults(futureValidationResults);
			}

			repository.synchronize();
		}
		LOG.info("{} loaded TSL from cached files in the repository", loadedTSL);
	}

	private OtherTrustedList getNonEUTrustedList(String countryCode) {
		if (Utils.isCollectionNotEmpty(otherTrustedLists)) {
			for (OtherTrustedList otherTrustedList : otherTrustedLists) {
				if (Utils.areStringsEqual(countryCode, otherTrustedList.getCountryCode())) {
					return otherTrustedList;
				}
			}
		}
		return null;
	}

	public void refresh() {
		LOG.debug("TSL Validation Job is starting ...");

		analyzeLOTLBasedModel();

		analyzeOtherTrustedLists();

		repository.synchronize();

		LOG.debug("TSL Validation Job is finishing ...");
	}

	private void analyzeLOTLBasedModel() {
		if (Utils.isStringEmpty(lotlUrl)) {
			LOG.warn("The LOTL url is not defined ! LOTL model is skipped");
			return;
		}

		TSLLoaderResult resultLoaderLOTL = null;
		Future<TSLLoaderResult> result = executorService.submit(new TSLLoader(dataLoader, lotlCode, lotlUrl));
		try {
			resultLoaderLOTL = result.get();
		} catch (Exception e) {
			LOG.error("Unable to load the LOTL : " + e.getMessage(), e);
			throw new DSSException("Unable to load the LOTL : " + e.getMessage(), e);
		}
		if (resultLoaderLOTL.getContent() == null) {
			LOG.error("Unable to load the LOTL: content is empty");
			throw new DSSException("Unable to load the LOTL: content is empty");
		}

		TSLValidationModel europeanModel = null;
		boolean newLotl = !repository.isLastCountryVersion(resultLoaderLOTL);
		if (newLotl) {
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
				LOG.error("Unable to parse the LOTL : " + e.getMessage(), e);
				return;
			}
		}

		String currentStringOjUrlString = repository.getActualOjUrl();
		
		String latestOjKeystore = getLatestOjKeystore(parseResult);
		if (latestOjKeystore != null && !latestOjKeystore.equals(currentStringOjUrlString)) {
			if (currentStringOjUrlString != null) {
				LOG.warn("OJ keystore is out-dated! Newer URL will be used");
			}
			repository.setActualOjUrl(latestOjKeystore);
		}

		checkLOTLLocation(parseResult);

		// Copy certificates from the OJ keystore
		List<CertificateToken> allowedLotlSigners = new ArrayList<CertificateToken>();
		allowedLotlSigners.addAll(ojContentKeyStore.getCertificates());

		if (isPivotLOTL(parseResult)) {
			extractAllowedLotlSignersFromPivots(parseResult, allowedLotlSigners);
		}

		if (checkLOTLSignature && ((europeanModel.getValidationResult() == null) || !europeanModel.getValidationResult().isValid())) {
			try {
				TSLValidationResult validationResult = validateLOTL(europeanModel, allowedLotlSigners);
				europeanModel.setValidationResult(validationResult);
			} catch (Exception e) {
				LOG.error("Unable to validate the LOTL : " + e.getMessage(), e);
			}
		}

		analyzeCountryPointers(parseResult.getPointers(), newLotl);
	}

	private void checkLOTLLocation(TSLParserResult parseResult) {
		List<TSLPointer> pointers = parseResult.getPointers();
		for (TSLPointer tslPointer : pointers) {
			if (Utils.areStringsEqual(lotlCode, tslPointer.getTerritory())) {
				if (!Utils.areStringsEqual(lotlUrl, tslPointer.getUrl())) {
					LOG.warn("The LOTL URL has been changed ! Please update your properties (new value : {})", tslPointer.getUrl());
				}
				break;
			}
		}
	}

	private void extractAllowedLotlSignersFromPivots(TSLParserResult parseResult, List<CertificateToken> allowedLotlSigners) {
		List<Future<TSLLoaderResult>> pivotLoaderResults = new LinkedList<Future<TSLLoaderResult>>();
		List<String> pivotUris = getPivotUris(parseResult);
		for (String pivotUrl : pivotUris) {
			pivotLoaderResults.add(executorService.submit(new TSLLoader(dataLoader, lotlCode, pivotUrl)));
		}

		for (Future<TSLLoaderResult> pivotLoaderResult : pivotLoaderResults) {
			try {
				TSLLoaderResult loaderResult = pivotLoaderResult.get();
				if (loaderResult != null && loaderResult.getContent() != null) {
					TSLValidationModel pivotModel = null;
					if (!repository.isLastPivotVersion(loaderResult)) {
						pivotModel = repository.storePivotInCache(loaderResult);
					} else {
						pivotModel = repository.getPivotByUrl(loaderResult.getUrl());
					}

					if (pivotModel.getFilepath() == null) {
						LOG.warn("No file found for url '{}'", loaderResult.getUrl());
						continue;
					}
					DSSDocument trustedList = new FileDocument(pivotModel.getFilepath());

					TSLParserResult pivotParseResult = pivotModel.getParseResult();
					if (pivotParseResult == null) {
						Future<TSLParserResult> parseResultFuture = executorService.submit(new TSLParser(trustedList));
						pivotParseResult = parseResultFuture.get();
					}

					TSLValidationResult pivotValidationResult = pivotModel.getValidationResult();
					if (checkLOTLSignature && (pivotValidationResult == null)) {
						TSLValidator tslValidator = new TSLValidator(trustedList, loaderResult.getCountryCode(), allowedLotlSigners);
						Future<TSLValidationResult> pivotValidationFuture = executorService.submit(tslValidator);
						pivotValidationResult = pivotValidationFuture.get();
					}

					if (pivotValidationResult.isValid()) {
						List<CertificateToken> certs = getCertificatesForLOTLPointer(loaderResult, pivotParseResult);
						allowedLotlSigners.clear();
						allowedLotlSigners.addAll(certs);
					} else {
						LOG.warn("Pivot '{}' is not valid", loaderResult.getUrl());
					}

				}
			} catch (Exception e) {
				LOG.error("Unable to validate the pivot LOTL : " + e.getMessage(), e);
			}

		}
	}

	private List<CertificateToken> getCertificatesForLOTLPointer(TSLLoaderResult loaderResult, TSLParserResult pivotParseResult) {
		List<TSLPointer> pointers = pivotParseResult.getPointers();
		for (TSLPointer tslPointer : pointers) {
			if (Utils.areStringsEqual(tslPointer.getTerritory(), lotlCode)) {
				return tslPointer.getPotentialSigners();
			}
		}
		LOG.warn("No LOTL pointer in pivot '{}'", loaderResult.getUrl());
		return new ArrayList<CertificateToken>();
	}

	/**
	 * This method returns the OJ url if present in LOTL.
	 * 
	 * @param parseResult
	 * 
	 * @return latest OJ Keystore URL
	 */
	private String getLatestOjKeystore(TSLParserResult parseResult) {
		List<String> englishSchemeInformationURIs = parseResult.getEnglishSchemeInformationURIs();
		for (String url : englishSchemeInformationURIs) {
			if (url.contains(ojDomainName)) {
				return url;
			}
		}
		LOG.error("Latest Official Journal Keystore is not found!");
		return null;
	}

	private boolean isPivotLOTL(TSLParserResult parseResult) {
		return Utils.isCollectionNotEmpty(getPivotUris(parseResult));
	}

	private List<String> getPivotUris(TSLParserResult parseResult) {
		List<String> pivotUris = new LinkedList<String>();
		LinkedList<String> englishSchemeInformationURIs = (LinkedList<String>) parseResult.getEnglishSchemeInformationURIs();
		// Pivots order is current T, T-1, T-2,...
		Iterator<String> itr = englishSchemeInformationURIs.descendingIterator();
		while (itr.hasNext()) {
			String uri = itr.next();
			if (!uri.contains(ojDomainName) && !uri.startsWith(lotlRootSchemeInfoUri)) {
				pivotUris.add(uri);
			}
		}
		return pivotUris;
	}

	private void analyzeCountryPointers(List<TSLPointer> pointers, boolean newLotl) {
		List<Future<TSLLoaderResult>> futureLoaderResults = new ArrayList<Future<TSLLoaderResult>>();
		for (TSLPointer tslPointer : pointers) {
			if (Utils.isCollectionEmpty(filterTerritories) || filterTerritories.contains(tslPointer.getTerritory())) {
				TSLLoader tslLoader = new TSLLoader(dataLoader, tslPointer.getTerritory(), tslPointer.getUrl());
				futureLoaderResults.add(executorService.submit(tslLoader));
			}
		}

		List<Future<TSLParserResult>> futureParseResults = new ArrayList<Future<TSLParserResult>>();
		List<Future<TSLValidationResult>> futureValidationResults = new ArrayList<Future<TSLValidationResult>>();
		for (Future<TSLLoaderResult> futureLoaderResult : futureLoaderResults) {
			try {
				TSLLoaderResult loaderResult = futureLoaderResult.get();
				if (loaderResult != null) {
					TSLValidationModel countryModel = null;
					if (!repository.isLastCountryVersion(loaderResult)) {
						countryModel = repository.storeInCache(loaderResult);
					} else {
						countryModel = repository.getByCountry(loaderResult.getCountryCode());
					}


					if (countryModel.getFilepath() == null) {
						LOG.warn("No file found for url '{}'", loaderResult.getUrl());
						continue;
					}
					DSSDocument trustedList = new FileDocument(countryModel.getFilepath());

					TSLParserResult countryParseResult = countryModel.getParseResult();
					if (countryParseResult == null) {
						futureParseResults.add(executorService.submit(new TSLParser(trustedList)));
					}

					if (checkTSLSignatures && (countryModel.getValidationResult() == null || newLotl)) {
						TSLValidator tslValidator = new TSLValidator(trustedList, loaderResult.getCountryCode(),
								getPotentialSigners(pointers, loaderResult.getCountryCode()));
						futureValidationResults.add(executorService.submit(tslValidator));
					}
				}
			} catch (Exception e) {
				LOG.error("Unable to load/parse TSL : " + e.getMessage(), e);
			}
		}

		storeParseResults(futureParseResults);
		storeValidationResults(futureValidationResults);
	}

	private void analyzeOtherTrustedLists() {
		if (Utils.isCollectionNotEmpty(otherTrustedLists)) {
			List<TSLPointer> pointers = new ArrayList<TSLPointer>();
			for (OtherTrustedList otherTrustedList : otherTrustedLists) {
				TSLPointer customPointer = new TSLPointer();
				customPointer.setTerritory(otherTrustedList.getCountryCode());
				customPointer.setUrl(otherTrustedList.getUrl());
				customPointer.setPotentialSigners(otherTrustedList.getTrustStore().getCertificates());
				pointers.add(customPointer);
			}
			analyzeCountryPointers(pointers, false);
		}
	}

	private void storeParseResults(List<Future<TSLParserResult>> futureParseResults) {
		for (Future<TSLParserResult> futureParseResult : futureParseResults) {
			try {
				TSLParserResult tslParserResult = futureParseResult.get();
				repository.updateParseResult(tslParserResult);
			} catch (Exception e) {
				LOG.error("Unable to get parsing result : " + e.getMessage(), e);
			}
		}
	}

	private void storeValidationResults(List<Future<TSLValidationResult>> futureValidationResults) {
		for (Future<TSLValidationResult> futureValidationResult : futureValidationResults) {
			try {
				TSLValidationResult tslValidationResult = futureValidationResult.get();
				repository.updateValidationResult(tslValidationResult);
			} catch (Exception e) {
				LOG.error("Unable to get validation result : " + e.getMessage(), e);
			}
		}
	}

	private List<CertificateToken> getPotentialSigners(List<TSLPointer> pointers, String countryCode) {
		if (Utils.isCollectionNotEmpty(pointers)) {
			for (TSLPointer tslPointer : pointers) {
				if (Utils.areStringsEqual(countryCode, tslPointer.getTerritory())) {
					return tslPointer.getPotentialSigners();
				}
			}
		}
		return Collections.emptyList();
	}

	private TSLValidationResult validateLOTL(TSLValidationModel validationModel, List<CertificateToken> allowedSigners) throws Exception {
		validationModel.setLotl(true);
		TSLValidator tslValidator = new TSLValidator(new FileDocument(validationModel.getFilepath()), lotlCode, allowedSigners);
		Future<TSLValidationResult> future = executorService.submit(tslValidator);
		return future.get();
	}

	private TSLParserResult parseLOTL(TSLValidationModel validationModel) throws Exception {
		Future<TSLParserResult> future = executorService.submit(new TSLParser(new FileDocument(validationModel.getFilepath())));
		return future.get();
	}

}
