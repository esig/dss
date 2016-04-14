package eu.europa.esig.dss.validation.process.bbb.vci;

import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyHashValidCheck;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyIdentifiedCheck;
import eu.europa.esig.dss.validation.process.bbb.vci.checks.SignaturePolicyIdentifierCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.x509.SignaturePolicy;
import eu.europa.esig.jaxb.policy.LevelConstraint;
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
		MultiValuesConstraint signaturePolicyConstraint = validationPolicy.getSignaturePolicyConstraint(context);

		ChainItem<XmlVCI> item = firstItem = signaturePolicyIdentifier(signaturePolicyConstraint);

		if (signature.isPolicyPresent()
				&& (!SignaturePolicy.NO_POLICY.equals(signature.getPolicyId()) && !SignaturePolicy.IMPLICIT_POLICY.equals(signature.getPolicyId()))) {
			item = item.setNextItem(signaturePolicyIdentified());

			item = item.setNextItem(signaturePolicyHashValid());
		}

	}

	private ChainItem<XmlVCI> signaturePolicyIdentifier(MultiValuesConstraint signaturePolicyConstraint) {
		return new SignaturePolicyIdentifierCheck(result, signature, signaturePolicyConstraint);
	}

	private ChainItem<XmlVCI> signaturePolicyIdentified() {
		LevelConstraint constraint = validationPolicy.getSignaturePolicyIdentifiedConstraint(context);
		return new SignaturePolicyIdentifiedCheck(result, signature, constraint);
	}

	private ChainItem<XmlVCI> signaturePolicyHashValid() {
		LevelConstraint constraint = validationPolicy.getSignaturePolicyPolicyHashValid(context);
		return new SignaturePolicyHashValidCheck(result, signature, constraint);
	}

}
