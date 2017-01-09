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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.ServiceInfoStatus;
import eu.europa.esig.dss.tsl.TLInfo;
import eu.europa.esig.dss.tsl.TSLConditionsForQualifiers;
import eu.europa.esig.dss.tsl.TSLLoaderResult;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.tsl.TSLServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.TSLValidationResult;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.util.MutableTimeDependentValues;
import eu.europa.esig.dss.util.TimeDependentValues;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class is a repository which allows to store TSL loading/parsing/validation results.
 *
 */
public class TSLRepository {

	private static final Logger logger = LoggerFactory.getLogger(TSLRepository.class);

	private String cacheDirectoryPath = System.getProperty("java.io.tmpdir") + File.separator + "dss-cache-tsl" + File.separator;

	private Map<String, TSLValidationModel> tsls = new HashMap<String, TSLValidationModel>();

	private TrustedListsCertificateSource trustedListsCertificateSource;

	public void setCacheDirectoryPath(String cacheDirectoryPath) {
		this.cacheDirectoryPath = cacheDirectoryPath;
	}

	public void setTrustedListsCertificateSource(TrustedListsCertificateSource trustedListsCertificateSource) {
		this.trustedListsCertificateSource = trustedListsCertificateSource;
	}

	public TSLValidationModel getByCountry(String countryIsoCode) {
		return tsls.get(countryIsoCode);
	}

	public Map<String, TSLValidationModel> getAllMapTSLValidationModels() {
		return Collections.unmodifiableMap(new TreeMap<String, TSLValidationModel>(tsls));
	}

	public void clearRepository() {
		try {
			Utils.cleanDirectory(new File(cacheDirectoryPath));
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
			if (Utils.isArrayEmpty(resultLoader.getContent())) {
				return true;
			}
			validationModel.setUrl(resultLoader.getUrl());
			validationModel.setLoadedDate(new Date());
			String lastSha256 = getSHA256(resultLoader.getContent());
			return Utils.areStringsEqual(lastSha256, validationModel.getSha256FileContent());
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
			byte[] data = Utils.toByteArray(fis);
			validationModel.setSha256FileContent(getSHA256(data));
		} catch (Exception e) {
			logger.error("Unable to read '" + filePath + "' : " + e.getMessage());
		} finally {
			Utils.closeQuietly(fis);
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
			Utils.write(resultLoader.getContent(), os);
		} catch (Exception e) {
			throw new DSSException("Cannot create file in cache : " + e.getMessage(), e);
		} finally {
			Utils.closeQuietly(os);
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

	void synchronize() {
		if (trustedListsCertificateSource != null) {
			Map<String, TSLValidationModel> allMapTSLValidationModels = getAllMapTSLValidationModels();
			for (Entry<String, TSLValidationModel> entry : allMapTSLValidationModels.entrySet()) {
				String countryCode = entry.getKey();
				TSLValidationModel model = entry.getValue();
				// Synchronize certpool
				if (!model.isCertificateSourceSynchronized()) {
					TSLParserResult parseResult = model.getParseResult();
					if (parseResult != null) {
						List<TSLServiceProvider> serviceProviders = parseResult.getServiceProviders();
						for (TSLServiceProvider serviceProvider : serviceProviders) {
							for (TSLService service : serviceProvider.getServices()) {
								for (CertificateToken certificate : service.getCertificates()) {
									// Update info
									trustedListsCertificateSource.removeCertificate(certificate);
									trustedListsCertificateSource.addCertificate(certificate, getServiceInfo(serviceProvider, service, countryCode));
								}
							}
						}
					}
					model.setCertificateSourceSynchronized(true);
				}

				// Synchronize tlInfos
				trustedListsCertificateSource.updateTlInfo(countryCode, getTlInfo(countryCode, model));

			}
			logger.info("Nb of loaded trusted lists : " + allMapTSLValidationModels.size());
			logger.info("Nb of trusted certificates : " + trustedListsCertificateSource.getNumberOfTrustedCertificates());
		}
	}

	private TLInfo getTlInfo(String countryCode, TSLValidationModel model) {
		TLInfo info = new TLInfo();
		info.setCountryCode(countryCode);
		info.setUrl(model.getUrl());
		info.setLastLoading(model.getLoadedDate());
		info.setLotl(model.isLotl());

		TSLParserResult parseResult = model.getParseResult();
		if (parseResult != null) {
			info.setIssueDate(parseResult.getIssueDate());
			info.setNextUpdate(parseResult.getNextUpdateDate());
			info.setSequenceNumber(parseResult.getSequenceNumber());
			info.setVersion(parseResult.getVersion());

			int nbServiceProviders = 0;
			int nbServices = 0;
			int nbCertificates = 0;
			List<TSLServiceProvider> serviceProviders = parseResult.getServiceProviders();
			if (serviceProviders != null) {
				nbServiceProviders = serviceProviders.size();
				for (TSLServiceProvider tslServiceProvider : serviceProviders) {
					List<TSLService> services = tslServiceProvider.getServices();
					if (services != null) {
						nbServices += services.size();
						for (TSLService tslService : services) {
							List<CertificateToken> certificates = tslService.getCertificates();
							nbCertificates += Utils.collectionSize(certificates);
						}
					}
				}
			}
			info.setNbServiceProviders(nbServiceProviders);
			info.setNbServices(nbServices);
			info.setNbCertificates(nbCertificates);
		}

		TSLValidationResult validationResult = model.getValidationResult();
		if (validationResult != null) {
			info.setWellSigned(validationResult.isValid());
		}

		return info;
	}

	private ServiceInfo getServiceInfo(TSLServiceProvider serviceProvider, TSLService service, String countryCode) {
		ServiceInfo serviceInfo = new ServiceInfo();

		serviceInfo.setTspName(serviceProvider.getName());
		serviceInfo.setTspTradeName(serviceProvider.getTradeName());
		serviceInfo.setTspPostalAddress(serviceProvider.getPostalAddress());
		serviceInfo.setTspElectronicAddress(serviceProvider.getElectronicAddress());

		serviceInfo.setServiceName(service.getName());

		final MutableTimeDependentValues<ServiceInfoStatus> status = new MutableTimeDependentValues<ServiceInfoStatus>();
		final TimeDependentValues<TSLServiceStatusAndInformationExtensions> serviceStatus = service.getStatusAndInformationExtensions();
		if (serviceStatus != null) {
			for (TSLServiceStatusAndInformationExtensions tslServiceStatus : serviceStatus) {
				final Map<String, List<Condition>> qualifiersAndConditions = getMapConditionsByQualifier(tslServiceStatus);
				final ServiceInfoStatus s = new ServiceInfoStatus(tslServiceStatus.getType(), tslServiceStatus.getStatus(), qualifiersAndConditions,
						tslServiceStatus.getAdditionalServiceInfoUris(), tslServiceStatus.getExpiredCertsRevocationInfo(), tslServiceStatus.getStartDate(),
						tslServiceStatus.getEndDate());

				status.addOldest(s);
			}
		}
		serviceInfo.setStatus(status);
		serviceInfo.setTlCountryCode(countryCode);
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

	public Map<String, TLInfo> getSummary() {
		if (trustedListsCertificateSource != null) {
			return Collections.unmodifiableMap(new TreeMap<String, TLInfo>(trustedListsCertificateSource.getSummary()));
		} else {
			return Collections.emptyMap();
		}
	}

}
