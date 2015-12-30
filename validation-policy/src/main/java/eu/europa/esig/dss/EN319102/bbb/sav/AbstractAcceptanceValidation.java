package eu.europa.esig.dss.EN319102.bbb.sav;

import java.util.Date;

import eu.europa.esig.dss.EN319102.bbb.AbstractBasicBuildingBlock;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.AbstractTokenProxy;
import eu.europa.esig.dss.validation.report.DiagnosticData;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public abstract class AbstractAcceptanceValidation<T extends AbstractTokenProxy> extends AbstractBasicBuildingBlock<XmlSAV> {

	protected final DiagnosticData diagnosticData;
	protected final T token;
	protected final Date currentTime;
	protected final ValidationPolicy validationPolicy;

	public AbstractAcceptanceValidation(DiagnosticData diagnosticData, T token, Date currentTime, ValidationPolicy validationPolicy) {
		super(new XmlSAV());

		this.token = token;
		this.diagnosticData = diagnosticData;
		this.currentTime = currentTime;
		this.validationPolicy = validationPolicy;
	}

}
