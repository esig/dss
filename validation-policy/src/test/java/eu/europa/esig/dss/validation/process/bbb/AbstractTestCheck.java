package eu.europa.esig.dss.validation.process.bbb;

import org.junit.jupiter.api.BeforeAll;

import eu.europa.esig.dss.i18n.I18nProvider;

public class AbstractTestCheck {
	
	protected static I18nProvider i18nProvider;
	
	@BeforeAll
	public static void init() {
		i18nProvider = new I18nProvider();
	}

}
