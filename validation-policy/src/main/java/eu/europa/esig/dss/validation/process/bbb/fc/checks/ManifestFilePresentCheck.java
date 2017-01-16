package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.jaxb.diagnostic.XmlContainerInfo;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ManifestFilePresentCheck extends ChainItem<XmlFC> {

	private final XmlContainerInfo containerInfo;

	private MessageTag message;
	private MessageTag error;

	public ManifestFilePresentCheck(XmlFC result, XmlContainerInfo containerInfo, LevelConstraint constraint) {
		super(result, constraint);
		this.containerInfo = containerInfo;
	}

	@Override
	protected boolean process() {
		if ("ASiC-S".equals(containerInfo.getContainerType())) { // ASiC-S no Manifest
			message = MessageTag.BBB_FC_IMFP_ASICS;
			error = MessageTag.BBB_FC_IMFP_ASICS_ANS;
			return Utils.isCollectionEmpty(containerInfo.getManifestFiles());
		} else { // ASiC-E one or more manifest
			message = MessageTag.BBB_FC_IMFP_ASICE;
			error = MessageTag.BBB_FC_IMFP_ASICE_ANS;
			return Utils.isCollectionNotEmpty(containerInfo.getManifestFiles());
		}
	}

	@Override
	protected MessageTag getMessageTag() {
		return message;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return error;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
