package eu.europa.esig.dss.EN319102.validation.vpftsp;

import java.util.Map;

import eu.europa.esig.dss.EN319102.bbb.Chain;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.validation.vpftsp.checks.TimestampBasicBuildingBlocksCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.validation.TimestampWrapper;

/**
 * 5.4 Validation process for time-stamps
 */
public class ValidationProcessForTimeStamps extends Chain<XmlValidationProcessTimestamps> {

	private final TimestampWrapper timestamp;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	public ValidationProcessForTimeStamps(TimestampWrapper timestamp, Map<String, XmlBasicBuildingBlocks> bbbs) {
		super(new XmlValidationProcessTimestamps());

		this.timestamp = timestamp;
		this.bbbs = bbbs;
	}

	@Override
	protected void initChain() {
		XmlBasicBuildingBlocks tspBBB = bbbs.get(timestamp.getId());
		if (tspBBB != null) {
			firstItem = timestampBasicBuildingBlocksValid(tspBBB);
		}
	}

	private ChainItem<XmlValidationProcessTimestamps> timestampBasicBuildingBlocksValid(XmlBasicBuildingBlocks timestampBBB) {
		return new TimestampBasicBuildingBlocksCheck(result, timestampBBB, getFailLevelConstraint());
	}

}
