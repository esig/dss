package eu.europa.esig.dss.web;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;

import eu.europa.esig.dss.utils.Utils;

public class WebappIT {

	private static final String BASE_URL = "http://localhost:8765/";

	private WebDriver driver;

	@Before
	public void init() {
		driver = new HtmlUnitDriver(false);
		driver.manage().timeouts().implicitlyWait(30, TimeUnit.SECONDS);
	}

	@Test
	public void home() {
		driver.get(BASE_URL + "home");
		assertFindTitleSpan();
	}

	@Test
	public void signature() {
		driver.get(BASE_URL + "nexu");
		assertFindTitleSpan();
	}

	@Test
	public void signatureStandalone() {
		driver.get(BASE_URL + "signature-standalone");
		assertFindTitleSpan();
	}

	@Test
	public void extension() {
		driver.get(BASE_URL + "extension");
		assertFindTitleSpan();
	}

	@Test
	public void validation() {
		driver.get(BASE_URL + "validation");
		assertFindTitleSpan();
	}

	@Test
	public void validationPolicy() {
		driver.get(BASE_URL + "validation-policy");
		assertFindTitleSpan();
	}

	@Test
	public void tslInfo() {
		driver.get(BASE_URL + "tsl-info");
		assertFindTitleSpan();
	}

	@Test
	public void tslInfoBE() {
		driver.get(BASE_URL + "tsl-info/be");
		assertFindTitleSpan();
	}

	@Test
	public void webservicesAvailable() {
		driver.get(BASE_URL + "services");
		List<WebElement> linksService = driver.findElements(By.tagName("a"));
		assertEquals(4, Utils.collectionSize(linksService));
	}

	@Test
	public void wsdlSignature() {
		driver.get(BASE_URL + "services/SignatureService?wsdl");
	}

	@Test
	public void wsdlValidate() {
		driver.get(BASE_URL + "services/soap/ValidationService?wsdl");
	}

	@Test
	public void restValidation() {
		driver.get(BASE_URL + "services/rest/validation?_wadl");
	}

	private void assertFindTitleSpan() {
		WebElement siteTitleElement = driver.findElement(By.xpath("//title"));
		assertNotNull(siteTitleElement);
		assertEquals("DSS WebApp", siteTitleElement.getText());
	}

	@After
	public void tearDown() {
		driver.quit();
	}

}
