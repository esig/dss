package eu.europa.esig.dss.EN319102.validation.vpfswatsp.checks.psv.checks;

import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlPSV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class PastCertificateValidationCheck extends ChainItem<XmlPSV> {

	private final XmlPCV pcv;

	public PastCertificateValidationCheck(XmlPSV result, XmlPCV pcv, LevelConstraint constraint) {
		super(result, constraint);

		this.pcv = pcv;
	}

	@Override
	protected boolean process() {
		if ((pcv != null) && (pcv.getConclusion() != null)) {
			Indication pcvIndication = pcv.getConclusion().getIndication();
			SubIndication pcvSubindication = pcv.getConclusion().getSubIndication();

			// INDETERMINATE cases are treated in following steps depending of POE
			return Indication.VALID.equals(pcvIndication)
					|| (Indication.INDETERMINATE.equals(pcvSubindication) && (SubIndication.REVOKED_NO_POE.equals(pcvSubindication)
							|| SubIndication.REVOKED_CA_NO_POE.equals(pcvSubindication) || SubIndication.OUT_OF_BOUNDS_NO_POE.equals(pcvSubindication)
							|| SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(pcvSubindication)));

		}
		return false;

	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.PSV_IPCVC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PSV_IPCVC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return pcv.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return pcv.getConclusion().getSubIndication();
	}

}
