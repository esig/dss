package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
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

import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLService;
import eu.europa.esig.dss.tsl.TSLServiceExtension;
import eu.europa.esig.dss.tsl.TSLServiceProvider;
import eu.europa.esig.dss.tsl.TSLValidationModel;

@RunWith(Parameterized.class)
public class TSLSParserTest {

	@Parameters(name = "TSL to parse {index} : {0}")
	public static Collection<Object[]> data() {
		File folder = new File("src/test/resources/tsls");
		Collection<File> listFiles = FileUtils.listFiles(folder, new String[] {
				"xml"
		}, true);
		Collection<Object[]> dataToRun = new ArrayList<Object[]>();
		for (File file : listFiles) {
			dataToRun.add(new Object[] {
					file
			});
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
	public void parseTSL() {
		TSLParser parser = new TSLParser();
		TSLValidationModel model = parser.parseTSL(fileToTest);
		assertNotNull(model);
		assertNotNull(model.getNextUpdateDate());
		assertNotNull(model.getIssueDate());
		assertTrue(StringUtils.isNotEmpty(model.getTerritory()));
		assertTrue(model.getSequenceNumber() > 0);
		List<TSLPointer> pointers = model.getPointers();
		assertTrue(CollectionUtils.isNotEmpty(pointers));
		for (TSLPointer tslPointer : pointers) {
			assertTrue(StringUtils.isNotEmpty(tslPointer.getMimeType()));
			assertTrue(StringUtils.isNotEmpty(tslPointer.getTerritory()));
			assertTrue(StringUtils.isNotEmpty(tslPointer.getUrl()));
			assertTrue(CollectionUtils.isNotEmpty(tslPointer.getPotentialSigners()));
		}

		List<TSLServiceProvider> serviceProviders = model.getServiceProviders();

		if (countriesWithoutTSP.contains(model.getTerritory())) {
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
					assertTrue(StringUtils.isNotEmpty(tslService.getStatus()));
					assertTrue(StringUtils.isNotEmpty(tslService.getType()));

					assertNotNull(tslService.getStartDate());
					List<TSLServiceExtension> extensions = tslService.getExtensions();
					if (CollectionUtils.isNotEmpty(extensions)) {
						for (TSLServiceExtension tslServiceExtension : extensions) {
							assertTrue(CollectionUtils.isNotEmpty(tslServiceExtension.getConditionsForQualifiers()));
						}
					}
				}
			}
		}
	}
}
