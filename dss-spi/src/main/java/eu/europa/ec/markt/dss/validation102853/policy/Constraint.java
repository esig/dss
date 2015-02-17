/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.policy;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.RuleUtils;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.rules.MessageTag;
import eu.europa.ec.markt.dss.validation102853.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import eu.europa.ec.markt.dss.validation102853.xml.XmlNode;

/**
 * This class represents a constraint and indicates its level: IGNORE, INFORM, WARN, FAIL.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class Constraint implements NodeName, NodeValue, AttributeName, AttributeValue, Indication, SubIndication {

	private static final Logger LOG = LoggerFactory.getLogger(Constraint.class);

	/**
	 * Diagnostic data containing all static information
	 */
	protected XmlDom diagnosticData;

	/**
	 * This field represents the {@code XmlNode} of the constraint
	 */
	protected XmlNode node;

	/**
	 * This field represents the simple {@code String} value of the constraint
	 */
	protected String value;

	/**
	 * This field represent the {@code List} of {@code String} values of the constraint
	 */
	private List<String> valueList;

	/**
	 * This field represents the simple {@code String} expected value of the constraint
	 */
	protected String expectedValue;

	/**
	 * This field represents the list of acceptable identifiers
	 */
	protected List<String> identifiers;
	protected String indication;

	protected String subIndication;

	protected MessageTag failureMessageTag;
	protected Map<String, String> messageAttributes = new HashMap<String, String>();
	protected Conclusion conclusion;

	public static enum Level {IGNORE, INFORM, WARN, FAIL}

	private Level level;

	/**
	 * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
	 * {@code Level} then the {@code DSSException} is raised.
	 *
	 * @param level the constraint level string.
	 */
	public Constraint(final String level) throws DSSException {

		try {
			this.level = Level.valueOf(level.trim().toUpperCase());
		} catch (IllegalArgumentException e) {

			throw new DSSException("The validation policy configuration file should be checked: " + e.getMessage(), e);
		}
	}

	/**
	 * This method creates the constraint {@code XmlNode}.
	 *
	 * @param parentNode Represents the parent {@code XmlNode} to which the constraint node should be attached.
	 * @param messageTag is the message describing the constraint.
	 * @return the {@code XmlNode} representing the current constraint in the validation process
	 */
	public XmlNode create(final XmlNode parentNode, final MessageTag messageTag) {

		this.node = parentNode.addChild(CONSTRAINT);
		this.node.addChild(NAME, messageTag.getMessage()).setAttribute(NAME_ID, messageTag.name());
		return this.node;
	}

	/**
	 * This method creates the constraint {@code XmlNode}. This method should be used when the message describing the constraint comports dynamic parameters.
	 *
	 * @param parentNode Represents the parent {@code XmlNode} to which the constraint node should be attached.
	 * @param messageTag is the message describing the constraint.
	 * @param parameters the dynamic parameters to integrate into the message.
	 * @return the {@code XmlNode} representing the current constraint in the validation process.
	 */
	public XmlNode create(final XmlNode parentNode, final MessageTag messageTag, final String parameters) {

		this.node = parentNode.addChild(CONSTRAINT);
		final String message = String.format(messageTag.getMessage(), parameters);
		this.node.addChild(NAME, message).setAttribute(NAME_ID, messageTag.name());
		return this.node;
	}

	/**
	 * @return {@code XmlDom} representing encapsulated diagnostic data
	 */
	public XmlDom getDiagnosticData() {
		return diagnosticData;
	}

	/**
	 * Allows to link the diagnostic data to the {@code Constraint}
	 *
	 * @param diagnosticData {@code XmlDom} representing diagnostic data
	 */
	public void setDiagnosticData(final XmlDom diagnosticData) {
		this.diagnosticData = diagnosticData;
	}

	/**
	 * @param value the simple value of the constraint to set.
	 */
	public void setValue(final String value) {
		this.value = value;
	}

	/**
	 * @param booleanValue the simple value of the constraint to set. The {@code boolean} is converted to its {@code String} representation.
	 */
	public void setValue(final boolean booleanValue) {
		this.value = String.valueOf(booleanValue);
	}

	/**
	 * Sets the list of real values.
	 *
	 * @param stringList {@code List} of {@code String}s
	 */
	public void setValue(final List<String> stringList) {

		this.valueList = stringList;
	}

	/**
	 * @return the simple value of the constraint.
	 */
	public String getValue() {
		return value;
	}

	public String getExpectedValue() {
		return expectedValue;
	}

	/**
	 * @param expectedValue the simple expected value of the constraint to set.
	 */
	public void setExpectedValue(final String expectedValue) {
		this.expectedValue = expectedValue;
	}

	/**
	 * This method carry out the validation of the constraint.
	 *
	 * @return true if the constraint is met, false otherwise.
	 */
	public boolean check() {

		if (ignore()) {

			node.addChild(STATUS, IGNORED);
			return true;
		}
		if (inform()) {

			node.addChild(STATUS, INFORMATION);
			node.addChild(INFO, null, messageAttributes).setAttribute(EXPECTED_VALUE, expectedValue).setAttribute(CONSTRAINT_VALUE, value);
			return true;
		}
		boolean error = value.isEmpty();
		if (!error) {

			if (!"*".equals(expectedValue)) {

				error = expectedValue != null && !expectedValue.equals(value);
			}
		}
		if (error) {

			if (warn()) {

				node.addChild(STATUS, WARN);
				final XmlNode xmlNode = node.addChild(WARNING, failureMessageTag, messageAttributes);
				if (DSSUtils.isNotBlank(expectedValue) && !expectedValue.equals("true") && !expectedValue.equals("false")) {
					xmlNode.setAttribute(EXPECTED_VALUE, expectedValue).setAttribute(CONSTRAINT_VALUE, value);
				}
				conclusion.addWarning(failureMessageTag, messageAttributes);
				return true;
			}
			node.addChild(STATUS, KO);
			if (DSSUtils.isNotBlank(expectedValue) && !expectedValue.equals("true") && !expectedValue.equals("false")) {
				node.addChild(INFO).setAttribute(EXPECTED_VALUE, expectedValue).setAttribute(CONSTRAINT_VALUE, value);
			}
			if (DSSUtils.isNotBlank(indication)) {

				conclusion.setIndication(indication, subIndication);
			}
			conclusion.addError(failureMessageTag, messageAttributes);
			return false;
		}
		node.addChild(STATUS, OK);
		if (!messageAttributes.isEmpty()) {
			node.addChild(INFO, null, messageAttributes);
		}
		return true;
	}

	/**
	 * This method carries out the validation of the constraint.
	 *
	 * @return true if the constraint is met, false otherwise.
	 */
	public boolean checkInList() {

		if (ignore()) {

			node.addChild(STATUS, IGNORED);
			return true;
		}
		if (inform()) {

			node.addChild(STATUS, INFORMATION);
			node.addChild(INFO, null, messageAttributes).setAttribute("ExpectedValue", expectedValue).setAttribute("ConstraintValue", value);
			return true;
		}
		final boolean contains;
		if (value != null && "*".equals(expectedValue)) {
			contains = true;
		} else if (!DSSUtils.isEmpty(valueList)) {
			contains = valueList.containsAll(identifiers);
			value = valueList.toString();
		} else {
			contains = RuleUtils.contains1(value, identifiers);
		}
		if (!contains) {

			if (warn()) {

				node.addChild(STATUS, WARN);
				node.addChild(WARNING, failureMessageTag, messageAttributes).setAttribute(EXPECTED_VALUE, expectedValue).setAttribute(CONSTRAINT_VALUE, value);
				conclusion.addWarning(failureMessageTag, messageAttributes);
				return true;
			}
			node.addChild(STATUS, KO);
			node.addChild(INFO).setAttribute(EXPECTED_VALUE, expectedValue).setAttribute(CONSTRAINT_VALUE, value);
			conclusion.setIndication(indication, subIndication);
			conclusion.addError(failureMessageTag, messageAttributes);
			return false;
		}
		node.addChild(STATUS, OK);
		node.addChild(INFO, null, messageAttributes);
		return true;
	}

	/**
	 * @param indication        to return when failure
	 * @param subIndication     to return when failure
	 * @param failureMessageTag is the answer to be done in case of the constraint failure.
	 */
	public void setIndications(final String indication, final String subIndication, final MessageTag failureMessageTag) {

		this.indication = indication;
		this.subIndication = subIndication;
		this.failureMessageTag = failureMessageTag;
	}

	/**
	 * This method should be called when the failure of the constraint does not cause the failure of the process.
	 *
	 * @param failureMessageTag is the answer to be done in case of the constraint failure.
	 */
	public void setIndications(final MessageTag failureMessageTag) {

		this.failureMessageTag = failureMessageTag;
	}

	public void setConclusionReceiver(final Conclusion conclusion) {
		this.conclusion = conclusion;
	}

	/**
	 * @param identifiers the {@code List} of identifiers to set.
	 */
	public void setIdentifiers(final List<String> identifiers) {
		this.identifiers = identifiers;
	}

	public List<String> getIdentifiers() {
		return identifiers;
	}

	/**
	 * This method allows to add an attribute to the answer node (to the message).
	 *
	 * @param attributeName  the attribute name
	 * @param attributeValue the attribute value
	 */
	public Constraint setAttribute(final String attributeName, final String attributeValue) {

		messageAttributes.put(attributeName, attributeValue);
		return this;
	}

	/**
	 * This method returns the constraint's level.
	 *
	 * @return the {@code Level} of the constraint
	 */
	public Level getLevel() {
		return level;
	}

	/**
	 * Says if the constraint should be ignored.
	 *
	 * @return true if the constraint should be ignored.
	 */
	public boolean ignore() {
		return level.equals(Level.IGNORE);
	}

	/**
	 * Indicates if the constraint should only return information.
	 *
	 * @return true if the constraint should only return information.
	 */
	public boolean inform() {
		return level.equals(Level.INFORM);
	}

	/**
	 * Says if the result of the constraint should be considered as warning.
	 *
	 * @return true if the constraint should be considered as warning.
	 */
	public boolean warn() {
		return level.equals(Level.WARN);
	}

	/**
	 * Indicates whether the constraint should fail when it is not met.
	 *
	 * @return true if the constraint should fail.
	 */
	public boolean fail() {
		return level.equals(Level.FAIL);
	}
}
