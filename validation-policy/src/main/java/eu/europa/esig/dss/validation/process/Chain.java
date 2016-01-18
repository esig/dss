package eu.europa.esig.dss.validation.process;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public abstract class Chain<T extends XmlConstraintsConclusion> {

	protected final T result;

	protected ChainItem<T> firstItem;

	protected Chain(T newInstance) {
		this.result = newInstance;
	}

	public T execute() {
		initChain();

		if (firstItem != null) {
			firstItem.execute();
		}

		if (result.getConclusion() == null) {
			XmlConclusion conclusion = new XmlConclusion();
			conclusion.setIndication(Indication.VALID);
			result.setConclusion(conclusion);
		}

		addAdditionalInfo();

		return result;
	}

	protected void addAdditionalInfo() {
		// default is empty
	}

	protected abstract void initChain();

	// TODO uses validation policy
	protected LevelConstraint getFailLevelConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);
		return constraint;
	}

}
