package eu.europa.esig.dss.tsl.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.core.util.ExecutorServiceUtil;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class LOTLLoader {

	private static final Logger logger = LoggerFactory.getLogger(LOTLLoader.class);

	private DataLoader dataLoader;
	private KeyStoreCertificateSource dssKeyStore;

	public void setDataLoader(DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	public void setDssKeyStore(KeyStoreCertificateSource dssKeyStore) {
		this.dssKeyStore = dssKeyStore;
	}

	public Map<String, TSLValidationModel> loadLotlAndTsl(String lotlUrl) {

		Map<String, TSLValidationModel> map = new HashMap<String, TSLValidationModel>();

		ExecutorService service = ExecutorServiceUtil.newExecutorService();

		TSLLoader tslLoader = new TSLLoader(dataLoader, lotlUrl);
		Future<TSLValidationModel> future = service.submit(tslLoader);
		TSLValidationModel lotlModel;
		try {
			lotlModel = future.get();
			map.put(lotlModel.getTerritory(), lotlModel);
		} catch (Exception e) {
			throw new DSSException("Unable to load TSL : " + e.getMessage(), e);
		}

		List<TSLPointer> pointers = lotlModel.getPointers();
		List<Future<TSLValidationModel>> futures = new ArrayList<Future<TSLValidationModel>>();
		for (TSLPointer tslPointer : pointers) {
			map.put(tslPointer.getTerritory(), null);
			tslLoader = new TSLLoader(dataLoader, tslPointer.getUrl());
			futures.add(service.submit(tslLoader));
		}

		for (Future<TSLValidationModel> futureTSL : futures) {
			try {
				TSLValidationModel tslModel = futureTSL.get();
				map.put(tslModel.getTerritory(), tslModel);
			} catch (Exception e) {
				logger.error("Unable to parse " + e.getMessage(), e);
			}
		}

		TSLValidator validator = null;
		futures = new ArrayList<Future<TSLValidationModel>>();
		for (Entry<String, TSLValidationModel> entry : map.entrySet()) {
			TSLValidationModel validationModel = entry.getValue();
			if (validationModel != null) {
				validator = new TSLValidator(validationModel, dssKeyStore, getPotentialSigners(entry.getKey(), lotlModel));
				futures.add(service.submit(validator));
			}
		}

		for (Future<TSLValidationModel> futureTSL : futures) {
			try {
				TSLValidationModel tslModel = futureTSL.get();
				map.put(tslModel.getTerritory(), tslModel);
			} catch (Exception e) {
				logger.error("Unable to validate " + e.getMessage(), e);
			}
		}

		return map;
	}

	private List<CertificateToken> getPotentialSigners(String countryCode, TSLValidationModel lotlModel) {
		List<CertificateToken> certificates = new ArrayList<CertificateToken>();
		if ((lotlModel != null) && CollectionUtils.isNotEmpty(lotlModel.getPointers()) && StringUtils.isNotEmpty(countryCode)) {
			List<TSLPointer> lotlPointers = lotlModel.getPointers();
			for (TSLPointer tslPointer : lotlPointers) {
				if (countryCode.equals(tslPointer.getTerritory())) {
					return tslPointer.getPotentialSigners();
				}
			}
		}
		return certificates;
	}

}
