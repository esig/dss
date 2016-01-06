package eu.europa.esig.dss.EN319102;

import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.validation.bs.ValidationProcessForBasicSignatures;
import eu.europa.esig.dss.EN319102.validation.tsp.ValidationProcessForTimeStamps;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicSignaturesValidation;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlLongTermData;
import eu.europa.esig.dss.jaxb.detailedreport.XmlLongTermDataValidation;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.jaxb.detailedreport.XmlStatus;
import eu.europa.esig.dss.jaxb.detailedreport.XmlTimestampsValidation;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.DiagnosticData;

/**
 * 5.5 Validation process for Signatures with Time and Signatures with Long-Term Validation Data
 */
public class ValidationProcessForSignaturesWithLongTermValidationData {

	private final DiagnosticData diagnosticData;

	private final ValidationPolicy policy;

	private final Date currentTime;

	public ValidationProcessForSignaturesWithLongTermValidationData(DiagnosticData diagnosticData, ValidationPolicy policy, Date currentTime) {
		this.diagnosticData = diagnosticData;
		this.policy = policy;
		this.currentTime = currentTime;
	}

	public XmlLongTermDataValidation execute() {
		XmlLongTermDataValidation result = new XmlLongTermDataValidation();

		XmlBasicSignaturesValidation basicSignaturesValidation = runValidationProcessForBasicSignatures();

		boolean acceptableBasicSignature = validateBasicSignaturesValidation(result, basicSignaturesValidation);

		if (!acceptableBasicSignature) {
			return result;
		}

		XmlTimestampsValidation timestampsValidation = runValidationProcessForTimeStamps();

		return result;
	}

	private XmlBasicSignaturesValidation runValidationProcessForBasicSignatures() {
		ValidationProcessForBasicSignatures vpfbs = new ValidationProcessForBasicSignatures(diagnosticData, policy, currentTime);
		return vpfbs.execute();
	}

	private XmlConclusion getBasicBuildingBlocksConclusionBySignatureId(XmlBasicSignaturesValidation basicSignaturesValidation, String id) {
		List<XmlSignature> basicSignatures = basicSignaturesValidation.getSignatures();
		for (XmlSignature xmlSignature : basicSignatures) {
			if (StringUtils.equals(id, xmlSignature.getId()) && xmlSignature.getBasicBuildingBlocks() != null) {
				return xmlSignature.getBasicBuildingBlocks().getConclusion();
			}
		}
		return null;
	}

	private boolean validateBasicSignaturesValidation(XmlLongTermDataValidation result, XmlBasicSignaturesValidation basicSignaturesValidation) {
		boolean acceptableBasicSignature = false;
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (SignatureWrapper signature : signatures) {
				XmlLongTermData ltd = new XmlLongTermData();
				ltd.setSignatureId(signature.getId());

				XmlConclusion bbbConclusion = getBasicBuildingBlocksConclusionBySignatureId(basicSignaturesValidation, signature.getId());

				XmlConstraint constraint = new XmlConstraint();
				XmlName name = new XmlName();
				name.setNameId(MessageTag.ADEST_ROBVPIIC.name());
				name.setValue(MessageTag.ADEST_ROBVPIIC.getMessage());
				constraint.setName(name);

				if (isAcceptableBasicBuildingBlocksConclusion(bbbConclusion)) {
					acceptableBasicSignature = true;
					constraint.setStatus(XmlStatus.OK);
				} else {
					constraint.setStatus(XmlStatus.NOT_OK);
					ltd.setConclusion(bbbConclusion);
				}

				ltd.getConstraints().add(constraint);
				result.getLongTermData().add(ltd);
			}
		}
		return acceptableBasicSignature;
	}

	private boolean isAcceptableBasicBuildingBlocksConclusion(XmlConclusion bbbConclusion) {
		if (bbbConclusion != null) {
			Indication bbbIndication = bbbConclusion.getIndication();
			SubIndication bbbSubIndication = bbbConclusion.getSubIndication();

			return Indication.VALID.equals(bbbIndication)
					|| (Indication.INDETERMINATE.equals(bbbIndication) && (SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(bbbSubIndication)
							|| SubIndication.REVOKED_NO_POE.equals(bbbSubIndication) || SubIndication.OUT_OF_BOUNDS_NO_POE.equals(bbbSubIndication)));
		}
		return false;
	}

	private XmlTimestampsValidation runValidationProcessForTimeStamps() {
		ValidationProcessForTimeStamps vpftsp = new ValidationProcessForTimeStamps(diagnosticData, policy, currentTime);
		return vpftsp.execute();
	}

}
