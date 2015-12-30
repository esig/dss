package eu.europa.esig.dss.EN319102;

import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicSignaturesValidation;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.policy.rules.AttributeValue;
import eu.europa.esig.dss.validation.report.DiagnosticData;

/**
 * 5.3 Validation process for Basic Signatures
 */
public class ValidationProcessForBasicSignatures {

	private final DiagnosticData diagnosticData;

	private final ValidationPolicy mainPolicy;
	private final ValidationPolicy countersignaturePolicy;

	private final Date currentTime;

	public ValidationProcessForBasicSignatures(DiagnosticData diagnosticData, ValidationPolicy mainPolicy, ValidationPolicy countersignaturePolicy,
			Date currentTime) {
		this.diagnosticData = diagnosticData;
		this.mainPolicy = mainPolicy;
		this.countersignaturePolicy = countersignaturePolicy;
		this.currentTime = currentTime;
	}

	public XmlBasicSignaturesValidation execute() {

		XmlBasicSignaturesValidation result = new XmlBasicSignaturesValidation();

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (SignatureWrapper signature : signatures) {

				ValidationPolicy currentPolicy = mainPolicy;
				if (AttributeValue.COUNTERSIGNATURE.equals(signature.getType())) {
					currentPolicy = countersignaturePolicy;
				}

				BasicBuildingBlocks bbb = new BasicBuildingBlocks(diagnosticData, signature, currentTime, currentPolicy, Context.MAIN_SIGNATURE);
				XmlBasicBuildingBlocks basicBuildingBlocks = bbb.execute();

				XmlSignature signatureAnalysis = new XmlSignature();
				signatureAnalysis.setId(signature.getId());
				signatureAnalysis.setBasicBuildingBlocks(basicBuildingBlocks);
				result.getSignatures().add(signatureAnalysis);
			}
		}

		return result;
	}

}
