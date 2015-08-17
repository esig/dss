package eu.europa.esig.dss.tsl.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.core.util.ExecutorServiceUtil;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLValidationModel;

public class LOTLLoader {

	private static final Logger logger = LoggerFactory.getLogger(LOTLLoader.class);

	private TSLParser parser = new TSLParser();
	private DataLoader dataLoader;

	public void setDataLoader(DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	public Map<String, TSLValidationModel> loadLotlAndTsl(String lotlUrl) {

		Map<String, TSLValidationModel> map = new HashMap<String, TSLValidationModel>();

		ExecutorService service = ExecutorServiceUtil.newExecutorService();

		TSLLoader tslLoader = new TSLLoader(dataLoader, parser, lotlUrl);
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
			tslLoader = new TSLLoader(dataLoader, parser, tslPointer.getXmlUrl());
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

		return map;
	}

}
