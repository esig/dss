package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd;

import eu.europa.esig.dss.validation.process.Condition;

public abstract class AbstractSSCDCondition implements SSCDStrategy, Condition {

	@Override
	public SSCDStatus getSSCDStatus() {
		return check() ? SSCDStatus.SSCD : SSCDStatus.NOT_SSCD;
	}

}
