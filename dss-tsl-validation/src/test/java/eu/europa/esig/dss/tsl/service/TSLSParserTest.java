package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.tsl.TSLServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.util.TimeDependentValues;

@RunWith(Parameterized.class)
public class TSLSParserTest {

	@Parameters(name = "TSL to parse {index} : {0}")
	public static Collection<Object[]> data() {
		File folder = new File("src/test/resources/tsls");
		Collection<File> listFiles = FileUtils.listFiles(folder, new String[] { "xml" }, true);
		Collection<Object[]> dataToRun = new ArrayList<Object[]>();
		for (File file : listFiles) {
			dataToRun.add(new Object[] { file });
		}
		return dataToRun;
	}

	private static final List<String> countriesWithoutTSP;

	static {
		countriesWithoutTSP = new ArrayList<String>();
		countriesWithoutTSP.add("EU");
		countriesWithoutTSP.add("CY");
		countriesWithoutTSP.add("MT");
		countriesWithoutTSP.add("UK");
	}

	private File fileToTest;

	public TSLSParserTest(File fileToTest) {
		this.fileToTest = fileToTest;
	}

	@Test
	public void parseTSL() throws Exception {
		TSLParser parser = new TSLParser(new FileInputStream(fileToTest));
		TSLParserResult result = parser.call();
		assertNotNull(result);
		assertNotNull(result.getNextUpdateDate());
		assertNotNull(result.getIssueDate());
		assertTrue(StringUtils.isNotEmpty(result.getTerritory()));
		assertTrue(result.getSequenceNumber() > 0);
		List<TSLPointer> pointers = result.getPointers();
		assertTrue(CollectionUtils.isNotEmpty(pointers));
		for (TSLPointer tslPointer : pointers) {
			assertTrue(StringUtils.isNotEmpty(tslPointer.getMimeType()));
			assertTrue(StringUtils.isNotEmpty(tslPointer.getTerritory()));
			assertTrue(StringUtils.isNotEmpty(tslPointer.getUrl()));
			assertTrue(CollectionUtils.isNotEmpty(tslPointer.getPotentialSigners()));
		}

		List<TSLServiceProvider> serviceProviders = result.getServiceProviders();

		if (countriesWithoutTSP.contains(result.getTerritory())) {
			assertTrue(CollectionUtils.isEmpty(serviceProviders));
		} else {
			assertTrue(CollectionUtils.isNotEmpty(serviceProviders));
			for (TSLServiceProvider tslServiceProvider : serviceProviders) {
				assertTrue(StringUtils.isNotEmpty(tslServiceProvider.getName()));
				assertTrue(StringUtils.isNotEmpty(tslServiceProvider.getPostalAddress()));
				assertTrue(StringUtils.isNotEmpty(tslServiceProvider.getElectronicAddress()));
				List<TSLService> services = tslServiceProvider.getServices();
				assertTrue(CollectionUtils.isNotEmpty(services));
				for (TSLService tslService : services) {
					assertTrue(StringUtils.isNotEmpty(tslService.getName()));
					assertTrue(StringUtils.isNotEmpty(tslService.getType()));

					TimeDependentValues<TSLServiceStatusAndInformationExtensions> status = tslService.getStatusAndInformationExtensions();
					int n = 0;
					for (TSLServiceStatusAndInformationExtensions tslServiceStatus : status) {
						assertTrue(StringUtils.isNotEmpty(tslServiceStatus.getStatus()));
						assertNotNull(tslServiceStatus.getStartDate());
						++n;
					}
					assertTrue(n > 0);

				}
			}
		}
	}
}
