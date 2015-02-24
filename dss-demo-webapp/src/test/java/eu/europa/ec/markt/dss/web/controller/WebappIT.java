package eu.europa.ec.markt.dss.web.controller;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;

public class WebappIT {

	private static final String BASE_URL = "http://localhost:8080/dss-demo-webapp/";

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
