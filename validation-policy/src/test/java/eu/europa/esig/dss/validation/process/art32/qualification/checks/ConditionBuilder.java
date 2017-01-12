package eu.europa.esig.dss.validation.process.art32.qualification.checks;

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
