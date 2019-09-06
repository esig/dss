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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.util.TimeDependentValues;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.tsl.TSLServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.utils.Utils;

public class TSLSParserTest {

	public static Stream<Arguments> data() {
		File folder = new File("src/test/resources/tsls");
		Collection<File> listFiles = Utils.listFiles(folder, new String[] { "xml" }, true);
		Collection<Arguments> dataToRun = new ArrayList<Arguments>();
		for (File file : listFiles) {
			dataToRun.add(Arguments.of( file ));
		}
		return dataToRun.stream();
	}

	private static final List<String> countriesWithoutTSP;

	static {
		countriesWithoutTSP = new ArrayList<String>();
		countriesWithoutTSP.add("EU");
		countriesWithoutTSP.add("CY");
		countriesWithoutTSP.add("MT");
		countriesWithoutTSP.add("UK");
	}

	@ParameterizedTest(name = "TSL to parse {index} : {0}")
	@MethodSource("data")
	public void parseTSL(File fileToTest) throws Exception {
		TSLParser parser = new TSLParser(new FileDocument(fileToTest.getAbsolutePath()));
		TSLParserResult result = parser.call();
		assertNotNull(result);
		assertNotNull(result.getNextUpdateDate());
		assertNotNull(result.getIssueDate());
		assertTrue(Utils.isStringNotEmpty(result.getTerritory()));
		assertTrue(result.getSequenceNumber() > 0);
		List<TSLPointer> pointers = result.getPointers();
		assertTrue(Utils.isCollectionNotEmpty(pointers));
		for (TSLPointer tslPointer : pointers) {
			assertTrue(Utils.isStringNotEmpty(tslPointer.getMimeType()));
			assertTrue(Utils.isStringNotEmpty(tslPointer.getTerritory()));
			assertTrue(Utils.isStringNotEmpty(tslPointer.getUrl()));
			assertTrue(Utils.isCollectionNotEmpty(tslPointer.getPotentialSigners()));
		}

		List<TSLServiceProvider> serviceProviders = result.getServiceProviders();

		if (countriesWithoutTSP.contains(result.getTerritory())) {
			assertTrue(Utils.isCollectionEmpty(serviceProviders));
		} else {
			assertTrue(Utils.isCollectionNotEmpty(serviceProviders));
			for (TSLServiceProvider tslServiceProvider : serviceProviders) {
				assertTrue(Utils.isStringNotEmpty(tslServiceProvider.getName()));
				assertTrue(Utils.isStringNotEmpty(tslServiceProvider.getPostalAddress()));
				assertTrue(Utils.isStringNotEmpty(tslServiceProvider.getElectronicAddress()));
				List<TSLService> services = tslServiceProvider.getServices();
				assertTrue(Utils.isCollectionNotEmpty(services));
				for (TSLService tslService : services) {
					TimeDependentValues<TSLServiceStatusAndInformationExtensions> status = tslService.getStatusAndInformationExtensions();
					int n = 0;
					for (TSLServiceStatusAndInformationExtensions tslServiceStatus : status) {
						assertTrue(Utils.isStringNotEmpty(tslServiceStatus.getName()));
						assertTrue(Utils.isStringNotEmpty(tslServiceStatus.getStatus()));
						assertTrue(Utils.isStringNotEmpty(tslServiceStatus.getType()));
						assertNotNull(tslServiceStatus.getStartDate());
						++n;
					}
					assertTrue(n > 0);
				}
			}
		}
	}
}
