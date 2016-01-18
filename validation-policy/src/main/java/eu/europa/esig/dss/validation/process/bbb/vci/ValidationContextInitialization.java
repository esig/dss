package eu.europa.esig.dss.validation.process.bbb.vci;

import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyIdentifierCheck;
import eu.europa.esig.dss.validation.wrappers.SignatureWrapper;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

/**
 * 5.2.4 Validation context initialization This building block initializes the
 * validation constraints (chain constraints, cryptographic constraints,
 * signature elements constraints) and parameters (X.509 validation parameters
 * including trust anchors, certificate validation data) that will be used to
 * validate the signature.
 */
public class ValidationContextInitialization extends Chain<XmlVCI> {

	private final SignatureWrapper signature;

	private final Context context;
	private final ValidationPolicy validationPolicy;

	public ValidationContextInitialization(SignatureWrapper signature, Context context, ValidationPolicy validationPolicy) {
		super(new XmlVCI());

		this.signature = signature;
		this.context = context;
		this.validationPolicy = validationPolicy;
	}

	@Override
	protected void initChain() {
		firstItem = signaturePolicyIdentifier();
	}

	private ChainItem<XmlVCI> signaturePolicyIdentifier() {
		MultiValuesConstraint constraint = validationPolicy.getSignaturePolicyConstraint(context);
		return new SignaturePolicyIdentifierCheck(result, constraint, signature);
	}

}
