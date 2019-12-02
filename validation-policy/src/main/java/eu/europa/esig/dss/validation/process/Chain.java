/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

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
	
	protected boolean isValid(XmlConstraintsConclusion constraintConclusion) {
		return constraintConclusion != null && isValidConclusion(constraintConclusion.getConclusion());
	}

	protected boolean isValidConclusion(XmlConclusion conclusion) {
		return conclusion != null && Indication.PASSED.equals(conclusion.getIndication());
	}

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
