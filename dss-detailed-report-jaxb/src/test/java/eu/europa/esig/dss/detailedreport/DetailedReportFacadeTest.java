package eu.europa.esig.dss.detailedreport;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;

public class DetailedReportFacadeTest {

	@Test
	public void test() throws Exception {
		createAndValidate("dr1.xml");
	}

	@Test
	public void test2() throws Exception {
		createAndValidate("dr2.xml");
	}

	@Test
	public void tstTest() throws Exception {
		createAndValidate("dr-tst.xml");
	}

	@Test
	public void certTest() throws Exception {
		createAndValidate("dr-cert.xml");
	}

	@Test
	public void sigAndTstTest() throws Exception {
		createAndValidate("dr-sig-and-tst.xml");
	}
	
	private void createAndValidate(String filename) throws Exception {
		DetailedReportFacade facade = DetailedReportFacade.newFacade();

		XmlDetailedReport detailedReport = facade.unmarshall(new File("src/test/resources/" + filename));
		assertNotNull(detailedReport);

		String htmlReport = facade.generateHtmlReport(detailedReport);
		assertNotNull(htmlReport);

		htmlReport = facade.generateHtmlBootstrap3Report(detailedReport);
		assertNotNull(htmlReport);
	}

}
