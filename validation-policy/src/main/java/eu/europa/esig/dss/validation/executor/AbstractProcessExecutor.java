package eu.europa.esig.dss.validation.executor;

import java.util.Date;
import java.util.Locale;
import java.util.Objects;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.ValidationPolicy;

public class AbstractProcessExecutor {

	protected Date currentTime = new Date();
	protected ValidationPolicy policy;
	protected XmlDiagnosticData jaxbDiagnosticData;
	
	private I18nProvider i18nProvider;

	public void setCurrentTime(Date currentTime) {
		this.currentTime = currentTime;
	}

	public Date getCurrentTime() {
		return currentTime;
	}

	public void setDiagnosticData(XmlDiagnosticData diagnosticData) {
		this.jaxbDiagnosticData = diagnosticData;
	}

	public void setValidationPolicy(ValidationPolicy validationPolicy) {
		this.policy = validationPolicy;
	}

	public ValidationPolicy getValidationPolicy() {
		return policy;
	}

	public void setLocale(Locale locale) {
		i18nProvider = new I18nProvider(locale);
	}
	
	protected I18nProvider getI18nProvider() {
		if (i18nProvider == null) {
			i18nProvider = new I18nProvider(Locale.getDefault());
		}
		return i18nProvider;
	}
	
	protected void assertConfigurationValid() {
		Objects.requireNonNull(jaxbDiagnosticData, "The diagnostic data is missing");
		Objects.requireNonNull(policy, "The validation policy is missing");
		Objects.requireNonNull(currentTime, "The current time is missing");
	}

}
