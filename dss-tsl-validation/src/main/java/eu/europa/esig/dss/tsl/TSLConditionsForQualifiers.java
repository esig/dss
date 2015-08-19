package eu.europa.esig.dss.tsl;

import java.util.List;

public class TSLConditionsForQualifiers {

	private List<String> qualifiers;
	private Condition condition;

	public TSLConditionsForQualifiers(List<String> qualifiers, Condition condition) {
		this.qualifiers = qualifiers;
		this.condition = condition;
	}

	public List<String> getQualifiers() {
		return qualifiers;
	}

	public void setQualifiers(List<String> qualifiers) {
		this.qualifiers = qualifiers;
	}

	public Condition getCondition() {
		return condition;
	}

	public void setCondition(Condition condition) {
		this.condition = condition;
	}

}
