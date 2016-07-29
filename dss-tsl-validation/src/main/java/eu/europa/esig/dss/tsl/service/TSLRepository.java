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
import java.util.Map.Entry;
import java.util.TreeMap;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.ServiceInfoStatus;
import eu.europa.esig.dss.tsl.TSLConditionsForQualifiers;
import eu.europa.esig.dss.tsl.TSLLoaderResult;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.tsl.TSLServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.TSLValidationResult;
import eu.europa.esig.dss.tsl.TSLValidationSummary;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.util.MutableTimeDependentValues;
import eu.europa.esig.dss.util.TimeDependentValues;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class is a repository which allows to store TSL loading/parsing/validation results.
 *
 */
public class TSLRepository {

	private static final Logger logger = LoggerFactory.getLogger(TSLRepository.class);

	private String cacheDirectoryPath = System.getProperty("java.io.tmpdir") + File.separator + "dss-cache-tsl" + File.separator;

	private boolean allowExpiredTSLs = false;

	private boolean allowInvalidSignatures = false;

	private boolean allowIndeterminateSignatures = false;

	private Map<String, TSLValidationModel> tsls = new HashMap<String, TSLValidationModel>();

	private TrustedListsCertificateSource trustedListsCertificateSource;

	public void setCacheDirectoryPath(String cacheDirectoryPath) {
		this.cacheDirectoryPath = cacheDirectoryPath;
	}

	public void setAllowExpiredTSLs(boolean allowExpiredTSLs) {
		this.allowExpiredTSLs = allowExpiredTSLs;
	}

	public void setAllowInvalidSignatures(boolean allowInvalidSignatures) {
		this.allowInvalidSignatures = allowInvalidSignatures;
	}

	public void setAllowIndeterminateSignatures(boolean allowIndeterminateSignatures) {
		this.allowIndeterminateSignatures = allowIndeterminateSignatures;
	}

	public void setTrustedListsCertificateSource(TrustedListsCertificateSource trustedListsCertificateSource) {
		this.trustedListsCertificateSource = trustedListsCertificateSource;
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
					if (parseResult.getNextUpdateDate() == null || now.after(parseResult.getNextUpdateDate())) {
						continue;
					}
				}
			}
			if (!allowInvalidSignatures) {
				TSLValidationResult validationResult = tslValidationModel.getValidationResult();
				if (validationResult != null) {
					if (validationResult.isInvalid()) {
						continue;
					}
				}
			}
			if (!allowIndeterminateSignatures) {
				TSLValidationResult validationResult = tslValidationModel.getValidationResult();
				if (validationResult != null) {
					if (validationResult.isIndeterminate()) {
						continue;
					}
				}
			}
			result.add(tslValidationModel);
		}
		return Collections.unmodifiableList(result);
	}

	private List<TSLValidationModel> getSkippedTSLValidationModels() {
		List<TSLValidationModel> valids = getTSLValidationModels();
		Map<String, TSLValidationModel> all = getAllMapTSLValidationModels();
		List<TSLValidationModel> skippeds = new ArrayList<TSLValidationModel>();

		for (Entry<String, TSLValidationModel> entry : all.entrySet()) {
			boolean found = false;
			for (TSLValidationModel valid : valids) {
				if ((valid.getParseResult() != null) && entry.getKey().equals(valid.getParseResult().getTerritory())) {
					found = true;
					break;
				}
			}
			if (!found) {
				skippeds.add(entry.getValue());
			}
		}
		return skippeds;
	}

	public Map<String, TSLValidationModel> getAllMapTSLValidationModels() {
		return Collections.unmodifiableMap(new TreeMap<String, TSLValidationModel>(tsls));
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
			if (ArrayUtils.isEmpty(resultLoader.getContent())) {
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
		validationModel.setCertificateSourceSynchronized(false);
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
		validationModel.setCertificateSourceSynchronized(false);
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

	void synchronize() {
		if (trustedListsCertificateSource != null) {
			// Returns valid and not expired depending of configuration
			List<TSLValidationModel> tslValidationModels = getTSLValidationModels();
			for (TSLValidationModel model : tslValidationModels) {
				if (!model.isCertificateSourceSynchronized()) {
					boolean tlWellSigned = false;
					TSLValidationResult validationResult = model.getValidationResult();
					if ((validationResult != null) && validationResult.isValid()) {
						tlWellSigned = true;
					}

					TSLParserResult parseResult = model.getParseResult();
					if (parseResult != null) {
						List<TSLServiceProvider> serviceProviders = parseResult.getServiceProviders();
						for (TSLServiceProvider serviceProvider : serviceProviders) {
							for (TSLService service : serviceProvider.getServices()) {
								for (CertificateToken certificate : service.getCertificates()) {
									trustedListsCertificateSource.addCertificate(certificate, getServiceInfo(serviceProvider, service, tlWellSigned));
								}
							}
						}
					}
					model.setCertificateSourceSynchronized(true);
				}
			}

			List<TSLValidationModel> skippedTSLValidationModels = getSkippedTSLValidationModels();
			for (TSLValidationModel model : skippedTSLValidationModels) {
				if (!model.isCertificateSourceSynchronized()) {
					TSLParserResult parseResult = model.getParseResult();
					if (parseResult != null) {
						List<TSLServiceProvider> serviceProviders = parseResult.getServiceProviders();
						for (TSLServiceProvider serviceProvider : serviceProviders) {
							for (TSLService service : serviceProvider.getServices()) {
								for (CertificateToken certificate : service.getCertificates()) {
									if (trustedListsCertificateSource.removeCertificate(certificate)) {
										logger.info(certificate.getAbbreviation() + " is removed from trusted certificates");
									}
								}
							}
						}
					}
					model.setCertificateSourceSynchronized(true);
				}
			}

			logger.info("Nb of loaded trusted lists : " + tslValidationModels.size());
			logger.info("Nb of trusted certificates : " + trustedListsCertificateSource.getNumberOfTrustedCertificates());
			logger.info("Nb of skipped trusted lists : " + skippedTSLValidationModels.size());

			if (CollectionUtils.isNotEmpty(skippedTSLValidationModels)) {
				for (TSLValidationModel tslValidationModel : skippedTSLValidationModels) {
					logger.info(tslValidationModel.getUrl() + " is skipped");
				}
			}
		}
	}

	private ServiceInfo getServiceInfo(TSLServiceProvider serviceProvider, TSLService service, boolean tlWellSigned) {
		ServiceInfo serviceInfo = new ServiceInfo();

		serviceInfo.setTspName(serviceProvider.getName());
		serviceInfo.setTspTradeName(serviceProvider.getTradeName());
		serviceInfo.setTspPostalAddress(serviceProvider.getPostalAddress());
		serviceInfo.setTspElectronicAddress(serviceProvider.getElectronicAddress());

		serviceInfo.setServiceName(service.getName());
		serviceInfo.setType(service.getType());

		final MutableTimeDependentValues<ServiceInfoStatus> status = new MutableTimeDependentValues<ServiceInfoStatus>();
		final TimeDependentValues<TSLServiceStatusAndInformationExtensions> serviceStatus = service.getStatusAndInformationExtensions();
		if (serviceStatus != null) {
			for (TSLServiceStatusAndInformationExtensions tslServiceStatus : serviceStatus) {
				final Map<String, List<Condition>> qualifiersAndConditions = getMapConditionsByQualifier(tslServiceStatus);
				final ServiceInfoStatus s = new ServiceInfoStatus(tslServiceStatus.getStatus(), qualifiersAndConditions,
						tslServiceStatus.getAdditionalServiceInfoUris(), tslServiceStatus.getExpiredCertsRevocationInfo(), tslServiceStatus.getStartDate(),
						tslServiceStatus.getEndDate());

				status.addOldest(s);
			}
		}
		serviceInfo.setStatus(status);
		serviceInfo.setTlWellSigned(tlWellSigned);
		return serviceInfo;
	}

	private Map<String, List<Condition>> getMapConditionsByQualifier(TSLServiceStatusAndInformationExtensions tslServiceStatus) {
		List<TSLConditionsForQualifiers> conditionsForQualifiers = tslServiceStatus.getConditionsForQualifiers();
		final Map<String, List<Condition>> qualifiersAndConditions = new HashMap<String, List<Condition>>();
		if (conditionsForQualifiers != null) {
			for (TSLConditionsForQualifiers tslConditionsForQualifiers : conditionsForQualifiers) {
				Condition condition = tslConditionsForQualifiers.getCondition();
				for (String qualifier : tslConditionsForQualifiers.getQualifiers()) {
					List<Condition> conditionsForQualif = qualifiersAndConditions.get(qualifier);
					if (conditionsForQualif == null) {
						conditionsForQualif = new ArrayList<Condition>();
						qualifiersAndConditions.put(qualifier, conditionsForQualif);
					}
					conditionsForQualif.add(condition);
				}
			}
		}
		return qualifiersAndConditions;
	}

	public List<TSLValidationSummary> getSummary() {
		Map<String, TSLValidationModel> map = getAllMapTSLValidationModels();
		List<TSLValidationSummary> summaries = new ArrayList<TSLValidationSummary>();
		for (Entry<String, TSLValidationModel> entry : map.entrySet()) {
			String country = entry.getKey();
			TSLValidationModel model = entry.getValue();
			TSLValidationSummary summary = new TSLValidationSummary();
			summary.setCountry(country);
			summary.setLoadedDate(model.getLoadedDate());
			summary.setTslUrl(model.getUrl());

			TSLParserResult parseResult = model.getParseResult();
			if (parseResult != null) {
				summary.setSequenceNumber(parseResult.getSequenceNumber());
				summary.setIssueDate(parseResult.getIssueDate());
				summary.setNextUpdateDate(parseResult.getNextUpdateDate());

				int nbServiceProviders = 0;
				int nbServices = 0;
				int nbCertificatesAndX500Principals = 0;
				List<TSLServiceProvider> serviceProviders = parseResult.getServiceProviders();
				if (serviceProviders != null) {
					nbServiceProviders = serviceProviders.size();
					for (TSLServiceProvider tslServiceProvider : serviceProviders) {
						List<TSLService> services = tslServiceProvider.getServices();
						if (services != null) {
							nbServices += services.size();
							for (TSLService tslService : services) {
								List<CertificateToken> certificates = tslService.getCertificates();
								nbCertificatesAndX500Principals += CollectionUtils.size(certificates);
							}
						}
					}
				}
				summary.setNbServiceProviders(nbServiceProviders);
				summary.setNbServices(nbServices);
				summary.setNbCertificatesAndX500Principals(nbCertificatesAndX500Principals);
			}

			TSLValidationResult validationResult = model.getValidationResult();
			if (validationResult != null) {
				summary.setIndication(validationResult.getIndication());
			}

			summaries.add(summary);
		}
		return summaries;
	}

}
