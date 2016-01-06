package eu.europa.esig.dss.EN319102;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.policy.rules.Indication;

/**
 * 5.4 Validation process for time-stamps
 */
public class ValidationProcessForTimeStamps {

	private final XmlBasicBuildingBlocks timestampBBB;

	public ValidationProcessForTimeStamps(XmlBasicBuildingBlocks timestampBBB) {
		this.timestampBBB = timestampBBB;
	}

	public XmlValidationProcessTimestamps execute() {
		XmlValidationProcessTimestamps result = new XmlValidationProcessTimestamps();

		/*
		 * 1) Token signature validation: the building block shall perform the validation process for Basic Signatures
		 * as per clause 5.3 with the time-stamp token. In all the steps of this process, the building block shall take
		 * into account that the signature to validate is a time-stamp token (e.g. to select TSA trust-anchors). If this
		 * step
		 * returns PASSED, the building block shall go to the next step. Otherwise, the building block shall return the
		 * indication and information returned by the validation process.
		 */

		// Format check is skipped

		XmlISC isc = timestampBBB.getISC();
		XmlConclusion iscConclusion = isc.getConclusion();
		if (!Indication.VALID.equals(iscConclusion.getIndication())) {
			result.setConclusion(iscConclusion);
			return result;
		}

		// VCI is skipped

		XmlCV cv = timestampBBB.getCV();
		XmlConclusion cvConclusion = cv.getConclusion();
		if (!Indication.VALID.equals(cvConclusion.getIndication())) {
			result.setConclusion(cvConclusion);
			return result;
		}

		XmlXCV xcv = timestampBBB.getXCV();
		XmlConclusion xcvConclusion = xcv.getConclusion();
		if (!Indication.VALID.equals(xcvConclusion.getIndication())) {
			result.setConclusion(xcvConclusion);
			return result;
		}

		XmlSAV sav = timestampBBB.getSAV();
		XmlConclusion savConclusion = sav.getConclusion();
		if (!Indication.VALID.equals(savConclusion.getIndication())) {
			result.setConclusion(savConclusion);
			return result;
		}

		XmlConclusion conclusion = new XmlConclusion();
		conclusion.setIndication(Indication.VALID);
		result.setConclusion(conclusion);

		return result;
	}

}
