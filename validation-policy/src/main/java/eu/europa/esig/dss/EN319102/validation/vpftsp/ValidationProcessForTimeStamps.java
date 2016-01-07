package eu.europa.esig.dss.EN319102.validation.vpftsp;

import java.util.Map;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;

import eu.europa.esig.dss.EN319102.bbb.Chain;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.validation.vpftsp.checks.TimestampBasicBuildingBlocksCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.validation.TimestampWrapper;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.4 Validation process for time-stamps
 */
public class ValidationProcessForTimeStamps extends Chain<XmlValidationProcessTimestamps> {

	private final Set<TimestampWrapper> timestamps;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	public ValidationProcessForTimeStamps(Set<TimestampWrapper> timestamps, Map<String, XmlBasicBuildingBlocks> bbbs) {
		super(new XmlValidationProcessTimestamps());

		this.timestamps = timestamps;
		this.bbbs = bbbs;
	}

	@Override
	protected void initChain() {
		if (CollectionUtils.isNotEmpty(timestamps)) {
			ChainItem<XmlValidationProcessTimestamps> item = null;
			for (TimestampWrapper tsp : timestamps) {
				XmlBasicBuildingBlocks tspBasicBuldingBlocks = bbbs.get(tsp.getId());
				if (tspBasicBuldingBlocks != null) {
					if (firstItem == null) {
						item = firstItem = basicBuildingBlocks(tspBasicBuldingBlocks);
					} else {
						item = item.setNextItem(basicBuildingBlocks(tspBasicBuldingBlocks));
					}
				}
			}
		}
	}

	private ChainItem<XmlValidationProcessTimestamps> basicBuildingBlocks(XmlBasicBuildingBlocks timestampBBB) {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		return new TimestampBasicBuildingBlocksCheck(result, timestampBBB, constraint);
	}

}
