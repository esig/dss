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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
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

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
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

/**
 * This class is a repository which allows to store TSL loading/parsing/validation results.
 *
 */
public class TSLRepository {

	private static final Logger LOG = LoggerFactory.getLogger(TSLRepository.class);

	private String cacheDirectoryPath = System.getProperty("java.io.tmpdir") + File.separator + "dss-cache-tsl" + File.separator;

	private Map<String, TSLValidationModel> tsls = new HashMap<String, TSLValidationModel>();
	private Map<String, TSLValidationModel> pivots = new HashMap<String, TSLValidationModel>();
	private String ojActualUrl;

	private TrustedListsCertificateSource trustedListsCertificateSource;

	public void setCacheDirectoryPath(String cacheDirectoryPath) {
		this.cacheDirectoryPath = cacheDirectoryPath;
	}

	public String getCacheDirectoryPath() {
		return cacheDirectoryPath;
	}

	public void setTrustedListsCertificateSource(TrustedListsCertificateSource trustedListsCertificateSource) {
		this.trustedListsCertificateSource = trustedListsCertificateSource;
	}

	public TSLValidationModel getByCountry(String countryIsoCode) {
		return tsls.get(countryIsoCode);
	}

	public TSLValidationModel getPivotByUrl(String pivotUrl) {
		return pivots.get(pivotUrl);
	}
	
	public String getActualOjUrl() {
		return ojActualUrl;
	}
	
	public void setActualOjUrl(String ojActualUrl) {
		this.ojActualUrl = ojActualUrl;
	}

	public Map<String, TSLValidationModel> getAllMapTSLValidationModels() {
		return Collections.unmodifiableMap(new TreeMap<String, TSLValidationModel>(tsls));
	}

	public void clearRepository() throws IOException {
		Utils.cleanDirectory(new File(cacheDirectoryPath));
		tsls.clear();
	}

	boolean isLastCountryVersion(TSLLoaderResult resultLoader) {
		TSLValidationModel validationModel = getByCountry(resultLoader.getCountryCode());
		return isLastVersion(validationModel, resultLoader);
	}

	boolean isLastPivotVersion(TSLLoaderResult resultLoader) {
		TSLValidationModel validationModel = getPivotByUrl(resultLoader.getUrl());
		return isLastVersion(validationModel, resultLoader);
	}

	private boolean isLastVersion(TSLValidationModel validationModel, TSLLoaderResult resultLoader) {
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
		if (Utils.isArrayNotEmpty(resultLoader.getContent())) {
			validationModel.setCertificateSourceSynchronized(false);
			validationModel.setLoadedDate(new Date());
			validationModel.setSha256FileContent(getSHA256(resultLoader.getContent()));
			validationModel.setFilepath(storeOnFileSystem(resultLoader.getCountryCode(), resultLoader));
			LOG.info("New version of {} TSL is stored in cache", resultLoader.getCountryCode());
		}
		tsls.put(resultLoader.getCountryCode(), validationModel);
		return validationModel;
	}

	TSLValidationModel storePivotInCache(TSLLoaderResult resultLoader) {
		TSLValidationModel validationModel = new TSLValidationModel();
		validationModel.setUrl(resultLoader.getUrl());
		if (Utils.isArrayNotEmpty(resultLoader.getContent())) {
			validationModel.setSha256FileContent(getSHA256(resultLoader.getContent()));
			validationModel.setLoadedDate(new Date());
			String filename = resultLoader.getUrl();
			filename = filename.replaceAll("\\W", "_");
			validationModel.setFilepath(storeOnFileSystem(filename, resultLoader));
			LOG.info("New version of the pivot LOTL '{}' is stored in cache", resultLoader.getUrl());
		}
		pivots.put(resultLoader.getUrl(), validationModel);
		return validationModel;
	}

	void addParsedResultFromCacheToMap(TSLParserResult tslParserResult) {
		TSLValidationModel validationModel = new TSLValidationModel();
		String countryCode = tslParserResult.getTerritory();
		String filePath = getFilePath(countryCode);
		validationModel.setFilepath(filePath);
		try (FileInputStream fis = new FileInputStream(filePath)) {
			byte[] data = Utils.toByteArray(fis);
			validationModel.setSha256FileContent(getSHA256(data));
		} catch (Exception e) {
			LOG.error("Unable to read '{}' : {}", filePath, e.getMessage());
		}
		validationModel.setParseResult(tslParserResult);
		validationModel.setCertificateSourceSynchronized(false);
		tsls.put(countryCode, validationModel);
	}

	private String storeOnFileSystem(String filename, TSLLoaderResult resultLoader) {
		ensureCacheDirectoryExists();
		String filePath = getFilePath(filename);
		File fileToCreate = new File(filePath);
		try (FileOutputStream os = new FileOutputStream(fileToCreate)) {
			Utils.write(resultLoader.getContent(), os);
		} catch (Exception e) {
			throw new DSSException("Cannot create file in cache : " + e.getMessage(), e);
		}
		return filePath;
	}

	private void ensureCacheDirectoryExists() {
		File cacheDir = new File(cacheDirectoryPath);
		if (!cacheDir.exists() || !cacheDir.isDirectory()) {
			cacheDir.mkdirs();
		}
	}

	private String getFilePath(String filename) {
		return cacheDirectoryPath + filename + ".xml";
	}

	private String getSHA256(byte[] data) {
		return DatatypeConverter.printBase64Binary(DSSUtils.digest(DigestAlgorithm.SHA256, data));
	}

	List<File> getStoredFiles() {
		ensureCacheDirectoryExists();
		File cacheDir = new File(cacheDirectoryPath);
		LOG.info("TSL cache directory : {}", cacheDir);
		File[] listFiles = cacheDir.listFiles(new IgnorePivotFilenameFilter());
		return Arrays.asList(listFiles);
	}

	void synchronize() {
		if (trustedListsCertificateSource != null) {
			Map<String, TSLValidationModel> allMapTSLValidationModels = getAllMapTSLValidationModels();

			// We (re)-synchronize all countries. There're cases with certificates in more
			// than one TL (eg: First certification authority, a.s. in CZ/SK)
			if (isRefreshRequired()) {
				LOG.info("Synchronizing the trustedListsCertificateSource...");

				Map<CertificateToken, List<ServiceInfo>> servicesByCertMap = getServicesByCert(allMapTSLValidationModels.values());

				trustedListsCertificateSource.reinit();

				for (Entry<CertificateToken, List<ServiceInfo>> servicesByCertEntry : servicesByCertMap.entrySet()) {
					trustedListsCertificateSource.addCertificate(servicesByCertEntry.getKey(), servicesByCertEntry.getValue());
				}

				for (Entry<String, TSLValidationModel> entry : allMapTSLValidationModels.entrySet()) {
					String countryCode = entry.getKey();
					TSLValidationModel model = entry.getValue();

					model.setCertificateSourceSynchronized(true);
					// Synchronize tlInfos
					trustedListsCertificateSource.updateTlInfo(countryCode, getTlInfo(countryCode, model));
				}

				for (TSLValidationModel model : pivots.values()) {
					model.setCertificateSourceSynchronized(true);
				}

				LOG.info("Synchronization of the trustedListsCertificateSource : done");
			}

			LOG.info("Nb of loaded trusted lists : {}/{}", getNbParsed(allMapTSLValidationModels.values()), allMapTSLValidationModels.size());
			LOG.info("Nb of trusted certificates : {}", trustedListsCertificateSource.getNumberOfCertificates());
			LOG.info("Nb of trusted public keys : {}", trustedListsCertificateSource.getNumberOfTrustedPublicKeys());
		}
	}

	private int getNbParsed(Collection<TSLValidationModel> models) {
		int counter = 0;
		for (TSLValidationModel model : models) {
			if (model.getParseResult() != null) {
				counter++;
			}
		}
		return counter;
	}

	private boolean isRefreshRequired() {
		for (TSLValidationModel model : tsls.values()) {
			if (!model.isCertificateSourceSynchronized()) {
				return true;
			}
		}

		for (TSLValidationModel model : pivots.values()) {
			if (!model.isCertificateSourceSynchronized()) {
				return true;
			}
		}

		return false;
	}

	private Map<CertificateToken, List<ServiceInfo>> getServicesByCert(Collection<TSLValidationModel> models) {
		Map<CertificateToken, List<ServiceInfo>> servicesByCert = new HashMap<CertificateToken, List<ServiceInfo>>();
		for (TSLValidationModel model : models) {
			TSLParserResult parseResult = model.getParseResult();
			if (parseResult != null) {
				List<TSLServiceProvider> serviceProviders = parseResult.getServiceProviders();
				String countryCode = parseResult.getTerritory();
				for (TSLServiceProvider serviceProvider : serviceProviders) {
					for (TSLService service : serviceProvider.getServices()) {
						ServiceInfo serviceInfo = getServiceInfo(serviceProvider, service, countryCode);
						for (CertificateToken certificate : service.getCertificates()) {
							List<ServiceInfo> currentCertServices = servicesByCert.get(certificate);
							if (currentCertServices == null) {
								currentCertServices = new ArrayList<ServiceInfo>();
								servicesByCert.put(certificate, currentCertServices);
							}
							currentCertServices.add(serviceInfo);
						}
					}
				}
			} else {
				LOG.warn("Url '{}' is not synchronized", model.getUrl());
			}
		}
		return servicesByCert;
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
		serviceInfo.setTspRegistrationIdentifier(serviceProvider.getRegistrationIdentifier());
		serviceInfo.setTspPostalAddress(serviceProvider.getPostalAddress());
		serviceInfo.setTspElectronicAddress(serviceProvider.getElectronicAddress());

		final MutableTimeDependentValues<ServiceInfoStatus> status = new MutableTimeDependentValues<ServiceInfoStatus>();
		final TimeDependentValues<TSLServiceStatusAndInformationExtensions> serviceStatus = service.getStatusAndInformationExtensions();
		if (serviceStatus != null) {
			for (TSLServiceStatusAndInformationExtensions tslServiceStatus : serviceStatus) {
				final Map<String, List<Condition>> qualifiersAndConditions = getMapConditionsByQualifier(tslServiceStatus);
				final ServiceInfoStatus s = new ServiceInfoStatus(tslServiceStatus.getName(),
						tslServiceStatus.getType(), tslServiceStatus.getStatus(), qualifiersAndConditions,
						tslServiceStatus.getAdditionalServiceInfoUris(), tslServiceStatus.getServiceSupplyPoints(),
						tslServiceStatus.getExpiredCertsRevocationInfo(), tslServiceStatus.getStartDate(), tslServiceStatus.getEndDate());

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
