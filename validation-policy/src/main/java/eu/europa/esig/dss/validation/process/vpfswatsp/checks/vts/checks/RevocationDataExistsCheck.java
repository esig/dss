package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlVTS;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.wrappers.CertificateWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class RevocationDataExistsCheck extends ChainItem<XmlVTS> {

	private final CertificateWrapper certificate;

	public RevocationDataExistsCheck(XmlVTS result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(result, constraint);

		this.certificate = certificate;
	}

	@Override
	protected boolean process() {
		return certificate.getRevocationData() != null;
	}

	@Override
	protected MessageTag getMessageTag() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_POE;
	}

}
