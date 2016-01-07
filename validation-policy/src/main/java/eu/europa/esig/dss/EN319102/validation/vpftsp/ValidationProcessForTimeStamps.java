package eu.europa.esig.dss.EN319102.validation.vpftsp;

import eu.europa.esig.dss.EN319102.bbb.AbstractBasicBuildingBlock;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.validation.vpftsp.checks.TimestampBasicBuildingBlocksCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.4 Validation process for time-stamps
 */
public class ValidationProcessForTimeStamps extends AbstractBasicBuildingBlock<XmlValidationProcessTimestamps> {

	private final XmlBasicBuildingBlocks timestampBBB;

	public ValidationProcessForTimeStamps(XmlBasicBuildingBlocks timestampBBB) {
		super(new XmlValidationProcessTimestamps());

		this.timestampBBB = timestampBBB;
	}

	@Override
	protected void initChain() {
		firstItem = basicBuildingBlocks();
	}

	private ChainItem<XmlValidationProcessTimestamps> basicBuildingBlocks() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		return new TimestampBasicBuildingBlocksCheck(result, timestampBBB, constraint);
	}

}
