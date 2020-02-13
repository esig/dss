package eu.europa.esig.dss.simplereport;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;

public class SimpleReportFacadeTest {

	@Test
	public void test() throws Exception {
		createAndValidate("sr1.xml");
	}

	@Test
	public void test2() throws Exception {
		createAndValidate("sr2.xml");
	}

	@Test
	public void sigAndTstTest() throws Exception {
		createAndValidate("sr-sig-and-tst.xml");
	}
	
	private void createAndValidate(String filename) throws Exception {
		SimpleReportFacade facade = SimpleReportFacade.newFacade();

		XmlSimpleReport simpleReport = facade.unmarshall(new File("src/test/resources/" + filename));
		assertNotNull(simpleReport);

		String htmlReport = facade.generateHtmlReport(simpleReport);
		assertNotNull(htmlReport);

		htmlReport = facade.generateHtmlBootstrap3Report(simpleReport);
		assertNotNull(htmlReport);
	}

}
