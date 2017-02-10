package eu.europa.esig.dss.validation.process;

import eu.europa.esig.dss.validation.process.Condition;

public final class ConditionBuilder {

	private ConditionBuilder() {
	}

	public static Condition condTrue() {
		return new TrueCondition();
	}

	public static Condition condFalse() {
		return new FalseCondition();
	}

}
