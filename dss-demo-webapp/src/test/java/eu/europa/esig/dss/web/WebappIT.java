package eu.europa.esig.dss.web;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.commons.collections.CollectionUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;

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
		driver.get(BASE_URL + "signature");
		assertFindTitleSpan();
	}

	@Test
	public void webservicesAvailable() {
		driver.get(BASE_URL + "wservice");
		List<WebElement> linksWSDL = driver.findElements(By.tagName("a"));
		assertEquals(2, CollectionUtils.size(linksWSDL));
	}

	@Test
	public void wsdlSignature() {
		driver.get(BASE_URL + "wservice/signatureService?wsdl");
	}

	@Test
	public void wsdlValidate() {
		driver.get(BASE_URL + "wservice/validationService?wsdl");
	}

	private void assertFindTitleSpan() {
		WebElement siteTitleElement = driver.findElement(By.xpath("//span[contains(@class, 'site-title')]"));
		assertNotNull(siteTitleElement);
		assertEquals("DSS WebApp",siteTitleElement.getText());
	}

	@After
	public void tearDown() {
		driver.quit();
	}

}
