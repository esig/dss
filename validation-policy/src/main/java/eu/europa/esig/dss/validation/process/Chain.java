package eu.europa.esig.dss.validation.process;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * This class is part of the design pattern "Chain of responsibility".
 * 
 * All sub-classes need to implement the method initChain() which will define the {@code ChainItem} (constraints) to
 * execute.
 * 
 * The chain is builded as follow with the method {@link eu.europa.esig.dss.validation.process.ChainItem#setNextItem}.
 * 
 * @param <T>
 *            the class used as result. The selected class must extend {@code XmlConstraintsConclusion} which contains
 *            some constraints and a conclusion.
 * 
 * @see ChainItem
 */
public abstract class Chain<T extends XmlConstraintsConclusion> {

	/**
	 * The result object : a sub-class of {@code XmlConstraintsConclusion}
	 */
	protected final T result;

	/**
	 * The first item to execute the chain
	 */
	protected ChainItem<T> firstItem;

	/**
	 * Common constructor
	 * 
	 * @param newInstance
	 *            a new instance of the result object
	 */
	protected Chain(T newInstance) {
		this.result = newInstance;
	}

	/**
	 * This method allows to initialize and execute the complete chain until the first failure.
	 * 
	 * @return the complete result with constraints and final conclusion for the chain
	 */
	public T execute() {
		initChain();

		if (firstItem != null) {
			firstItem.execute();
		}

		if (result.getConclusion() == null) {
			XmlConclusion conclusion = new XmlConclusion();
			conclusion.setIndication(Indication.PASSED);
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

	protected LevelConstraint getWarnLevelConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.WARN);
		return constraint;
	}

	protected LevelConstraint getInfoLevelConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.INFORM);
		return constraint;
	}

	protected void collectErrorsWarnsInfos() {
		XmlConclusion conclusion = result.getConclusion();
		List<XmlConstraint> constraints = result.getConstraint();
		for (XmlConstraint xmlConstraint : constraints) {
			XmlName error = xmlConstraint.getError();
			if (error != null) {
				conclusion.getErrors().add(error);
			}
			XmlName warning = xmlConstraint.getWarning();
			if (warning != null) {
				conclusion.getWarnings().add(warning);
			}
			XmlName info = xmlConstraint.getInfo();
			if (info != null) {
				conclusion.getInfos().add(info);
			}
		}
	}

}
