package eu.europa.esig.dss.validation.process;

import eu.europa.esig.dss.validation.process.Condition;

public class TrueCondition implements Condition {

	@Override
	public boolean check() {
		return true;
	}

}
