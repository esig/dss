package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ContentTimestampCheck extends ChainItem<XmlSAV> {

	private final DiagnosticData diagnosticData;
	private final SignatureWrapper signature;

	public ContentTimestampCheck(XmlSAV result, DiagnosticData diagnosticData, SignatureWrapper signature, LevelConstraint constraint) {
		super(result, constraint);
		this.diagnosticData = diagnosticData;
		this.signature = signature;
	}

	@Override
	protected boolean process() {
		List<TimestampWrapper> timestampsBySignature = diagnosticData.getTimestampList(signature.getId());

		for (TimestampWrapper timestampWrapper : timestampsBySignature) {
			if (TimestampType.CONTENT_TIMESTAMP.name().equals(timestampWrapper.getType())
					|| TimestampType.ALL_DATA_OBJECTS_TIMESTAMP.name().equals(timestampWrapper.getType())
					|| TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP.name().equals(timestampWrapper.getType())) {
				return true;
			}
		}

		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_SAV_ISQPCTSIP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_SAV_ISQPCTSIP_ANS;
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
