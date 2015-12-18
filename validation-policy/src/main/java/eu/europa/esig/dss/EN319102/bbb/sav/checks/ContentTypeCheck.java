package eu.europa.esig.dss.EN319102.bbb.sav.checks;

import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.ValueConstraint;

public class ContentTypeCheck extends ChainItem<XmlSAV> {

	private static final String ALL_VALUE = "*";

	private final SignatureWrapper signature;
	private final ValueConstraint constraint;

	public ContentTypeCheck(XmlSAV result, SignatureWrapper signature, ValueConstraint constraint) {
		super(result, constraint);
		this.signature = signature;
		this.constraint = constraint;
	}

	@Override
	protected boolean process() {
		String contentType = signature.getContentType();
		if (StringUtils.isEmpty(contentType)) {
			return false;
		}

		String expectedValue = constraint.getValue();
		if (ALL_VALUE.equals(expectedValue)) {
			return true;
		} else {
			return StringUtils.equals(expectedValue, contentType);
		}
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_SAV_ISQPCTP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_SAV_ISQPCTP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INVALID;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
