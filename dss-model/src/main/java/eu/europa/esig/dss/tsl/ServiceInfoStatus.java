package eu.europa.esig.dss.tsl;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.util.BaseTimeDependent;

public class ServiceInfoStatus extends BaseTimeDependent implements Serializable {

	private static final long serialVersionUID = 4258613511229825596L;

	/**
	 * <tsl:TrustServiceProvider><tsl:TSPServices><tsl:TSPService><tsl:ServiceInformation><tsl:ServiceStatus>
	 */
	private String status;

	private Map<String, List<Condition>> qualifiersAndConditions;

	public ServiceInfoStatus(String status, Map<String, List<Condition>> qualifiersAndConditions, Date startDate, Date endDate) {
		super( startDate, endDate );
		this.status = status;
		this.qualifiersAndConditions = qualifiersAndConditions;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	/**
	 * Add a qualifier and the corresponding conditionEntry
	 *
	 * @param qualifier
	 * @param condition
	 */
	public void addQualifierAndCondition(String qualifier, Condition condition) {
		List<Condition> conditions = qualifiersAndConditions.get(qualifier);
		if (conditions == null) {

			conditions = new ArrayList<Condition>();
			qualifiersAndConditions.put(qualifier, conditions);
		}
		conditions.add(condition);
	}

	public Map<String, List<Condition>> getQualifiersAndConditions() {
		return qualifiersAndConditions;
	}

// from toString()
//	for (final Entry<String, List<Condition>> conditionEntry : qualifiersAndConditions.entrySet()) {
//
//		buffer.append(indent).append("QualifiersAndConditions    \t= ").append(conditionEntry.getKey()).append(":").append('\n');
//		indent += "\t\t\t\t\t\t\t\t";
//
//		final List<Condition> conditions = conditionEntry.getValue();
//		for (final Condition condition : conditions) {
//
//			buffer.append(condition.toString(indent));
//		}
//		indent = indent.substring(8);
//	}

	
}
