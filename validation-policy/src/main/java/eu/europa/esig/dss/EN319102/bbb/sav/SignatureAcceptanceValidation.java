package eu.europa.esig.dss.EN319102.bbb.sav;

import eu.europa.esig.dss.EN319102.bbb.AbstractBasicBuildingBlock;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.bbb.sav.checks.SigningTimeCheck;
import eu.europa.esig.dss.EN319102.bbb.sav.checks.StructuralValidationCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.policy.ValidationPolicy2;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.2.8 Signature acceptance validation (SAV)
 * This building block covers any additional verification to be performed on the signature itself or on the attributes of the signature ETSI EN 319 132-1
 */
public class SignatureAcceptanceValidation extends AbstractBasicBuildingBlock<XmlSAV> {

	private final DiagnosticData diagnosticData;
	private final SignatureWrapper signature;

	private final ValidationPolicy2 validationPolicy;

	private ChainItem<XmlSAV> firstItem;
	private XmlSAV result = new XmlSAV();

	public SignatureAcceptanceValidation(DiagnosticData diagnosticData, SignatureWrapper signature, ValidationPolicy2 validationPolicy) {
		this.diagnosticData = diagnosticData;
		this.signature = signature;

		this.validationPolicy = validationPolicy;
	}

	@Override
	public void initChain() {
		ChainItem<XmlSAV> item = firstItem = structuralValidation();

		item = item.setNextItem(signingTime());

	}

	private ChainItem<XmlSAV> structuralValidation() {
		LevelConstraint constraint = validationPolicy.getStructuralValidationConstraint();
		return new StructuralValidationCheck(result, signature, constraint);
	}

	private ChainItem<XmlSAV> signingTime() {
		LevelConstraint constraint = validationPolicy.getSigningTimeConstraint();
		return new SigningTimeCheck(result, signature, constraint);
	}

	@Override
	public XmlSAV execute() {
		firstItem.execute();
		return result;
	}

}
