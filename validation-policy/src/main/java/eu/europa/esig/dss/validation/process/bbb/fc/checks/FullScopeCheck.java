package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.validation.SignatureScopeType;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.IMessageTag;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class FullScopeCheck extends ChainItem<XmlFC> {

	private final SignatureWrapper signature;

	public FullScopeCheck(XmlFC result, SignatureWrapper signature, LevelConstraint constraint) {
		super(result, constraint);

		this.signature = signature;
	}

	@Override
	protected boolean process() {
		boolean result = true;
		
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		for (XmlSignatureScope sigScope : signatureScopes) {
			result &= (SignatureScopeType.FULL == sigScope.getScope());
		}

		return result;
	}

	@Override
	protected IMessageTag getMessageTag() {
		return MessageTag.BBB_FC_ICFD;
	}

	@Override
	protected IMessageTag getErrorMessageTag() {
		return MessageTag.BBB_FC_ICFD_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
