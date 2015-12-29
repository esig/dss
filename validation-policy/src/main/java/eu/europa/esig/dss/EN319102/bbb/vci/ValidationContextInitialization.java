package eu.europa.esig.dss.EN319102.bbb.vci;

import eu.europa.esig.dss.EN319102.bbb.AbstractBasicBuildingBlock;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.bbb.vci.checks.SignaturePolicyIdentifierCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.policy.ValidationPolicy2;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.2.4 Validation context initialization
 * This building block initializes the validation constraints (chain constraints, cryptographic constraints, signature
 * elements constraints) and parameters (X.509 validation parameters including trust anchors, certificate validation data)
 * that will be used to validate the signature.
 */
public class ValidationContextInitialization extends AbstractBasicBuildingBlock<XmlVCI> {

	private final SignatureWrapper signature;
	private final ValidationPolicy2 validationPolicy;
	
	private ChainItem<XmlVCI> firstItem;
	private XmlVCI result = new XmlVCI();
	
	
	public ValidationContextInitialization(SignatureWrapper signature, ValidationPolicy2 validationPolicy) {
		this.signature = signature;
		this.validationPolicy = validationPolicy;
	}
	
	@Override
	public void initChain() {
		firstItem = signaturePolicyIdentifier();
	}
	
	private ChainItem<XmlVCI> signaturePolicyIdentifier() {
		LevelConstraint constraint = validationPolicy.getStructuralValidationConstraint();
		return new SignaturePolicyIdentifierCheck(result, constraint, signature);
	}
	
	@Override
	public XmlVCI execute() {
		firstItem.execute();
		return result;
	}

}
