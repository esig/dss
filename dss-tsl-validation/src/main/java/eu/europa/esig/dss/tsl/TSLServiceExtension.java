package eu.europa.esig.dss.tsl;

import java.util.List;

public class TSLServiceExtension {

	private boolean critical;
	private List<TSLConditionsForQualifiers> conditionsForQualifiers;

	public boolean isCritical() {
		return critical;
	}

	public void setCritical(boolean critical) {
		this.critical = critical;
	}

	public List<TSLConditionsForQualifiers> getConditionsForQualifiers() {
		return conditionsForQualifiers;
	}

	public void setConditionsForQualifiers(List<TSLConditionsForQualifiers> conditionsForQualifiers) {
		this.conditionsForQualifiers = conditionsForQualifiers;
	}

}
