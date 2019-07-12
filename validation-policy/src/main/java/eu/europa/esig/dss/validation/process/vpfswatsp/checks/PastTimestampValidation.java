package eu.europa.esig.dss.validation.process.vpfswatsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.IMessageTag;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class PastTimestampValidation extends ChainItem<XmlValidationProcessArchivalData> {
	
	private XmlPSV xmlPSV;
	private XmlSAV xmlSAV;

	private Indication indication;
	private SubIndication subIndication;
	
	private static final String PSV_BLOCK_SUFFIX = "-PSV";

	public PastTimestampValidation(XmlValidationProcessArchivalData result, XmlPSV xmlPSV, XmlSAV xmlSAV, 
			TimestampWrapper timestamp, LevelConstraint constraint) {
		super(result, constraint, timestamp.getId() + PSV_BLOCK_SUFFIX);
		this.xmlPSV = xmlPSV;
		this.xmlSAV = xmlSAV;
	}

	@Override
	protected boolean process() {
		if (!isValid(xmlPSV)) {
			indication = xmlPSV.getConclusion().getIndication();
			subIndication = xmlPSV.getConclusion().getSubIndication();
			return false;
		} else if (!isValid(xmlSAV)) {
			indication = xmlSAV.getConclusion().getIndication();
			subIndication = xmlSAV.getConclusion().getSubIndication();
			return false;
		}
		return true;
	}

	@Override
	protected IMessageTag getMessageTag() {
		return MessageTag.PSV_IPTVC;
	}

	@Override
	protected IMessageTag getErrorMessageTag() {
		return MessageTag.PSV_IPTVC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return indication;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return subIndication;
	}

}
