package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FormatCheck;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

/**
 * 5.2.2 Format Checking
 * 
 * This building block shall check that the signature to validate is conformant
 * to the applicable base format (e.g. CMS [i.8], CAdES [i.2], XML-DSig [i.11],
 * XAdES [i.4], etc.) prior to any subsequent processing.
 */
public class FormatChecking extends Chain<XmlFC> {

	private final SignatureWrapper signature;

	private final Context context;
	private final ValidationPolicy policy;

	public FormatChecking(SignatureWrapper signature, Context context, ValidationPolicy policy) {
		super(new XmlFC());

		this.signature = signature;
		this.context = context;
		this.policy = policy;
	}

	@Override
	protected void initChain() {
		firstItem = formatCheck();
	}

	private ChainItem<XmlFC> formatCheck() {
		MultiValuesConstraint constraint = policy.getSignatureFormatConstraint(context);
		return new FormatCheck(result, signature, constraint);
	}

}
