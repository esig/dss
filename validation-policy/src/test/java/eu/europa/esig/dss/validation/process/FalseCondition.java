package eu.europa.esig.dss.validation.process;

import eu.europa.esig.dss.validation.process.Condition;

public class FalseCondition implements Condition {

	@Override
	public boolean check() {
		return false;
	}

}
