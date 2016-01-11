package eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.psv;

import java.util.Date;

import eu.europa.esig.dss.EN319102.bbb.BasicBuildingBlocks;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.dss.validation.report.DiagnosticData;

public class PastSignatureValidation {

	private final DiagnosticData diagnosticData;
	private final TokenProxy token;
	private final Date nextArchiveTspProductionDate;
	private final ValidationPolicy policy;
	private final Context context;

	public PastSignatureValidation(DiagnosticData diagnosticData, TokenProxy token, Date nextArchiveTspProductionDate, ValidationPolicy policy,
			Context context) {
		this.diagnosticData = diagnosticData;
		this.token = token;
		this.nextArchiveTspProductionDate = nextArchiveTspProductionDate;
		this.policy = policy;
		this.context = context;

	}

	public XmlBasicBuildingBlocks execute() {
		BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, token, nextArchiveTspProductionDate, policy, context);
		return bbb.execute();
		// TODO bbbs.put(token.getId(), result); // replace ?
	}

}
