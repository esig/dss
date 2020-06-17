package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

public class SignedFilesPresentCheck extends ChainItem<XmlFC> {

	private final XmlContainerInfo containerInfo;

	private MessageTag message;
	private MessageTag error;

	public SignedFilesPresentCheck(I18nProvider i18nProvider, XmlFC result, XmlContainerInfo containerInfo, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.containerInfo = containerInfo;
	}

	@Override
	protected boolean process() {
		if ("ASiC-S".equals(containerInfo.getContainerType())) { // ASiC-S one signed file in the root directory
			message = MessageTag.BBB_FC_ISFP_ASICS;
			error = MessageTag.BBB_FC_ISFP_ASICS_ANS;
			List<String> contentFiles = containerInfo.getContentFiles();
			if (Utils.isCollectionNotEmpty(contentFiles) && contentFiles.size() == 1) {
				String fileName = contentFiles.iterator().next();
				return isRootDirectoryFile(fileName);
			}
			return false;
		} else { // ASiC-E one or more signed files outside META-INF
			message = MessageTag.BBB_FC_ISFP_ASICE;
			error = MessageTag.BBB_FC_ISFP_ASICE_ANS;
			return Utils.isCollectionNotEmpty(containerInfo.getContentFiles());
		}
	}
	
	private boolean isRootDirectoryFile(String fileName) {
		return !fileName.contains("/") && !fileName.contains("\\");
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
		return SubIndication.FORMAT_FAILURE;
	}

}
