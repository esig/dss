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
package eu.europa.esig.dss.validation.report;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.XmlNode;
import eu.europa.esig.dss.validation.policy.rules.AttributeName;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.NodeName;

/**
 * This class represents the conclusion (result) of the process, with at least the Indication, SubIndication (if any)...
 * This class can be derived to handle specific needs of the process.
 *
 *
 */
public class Conclusion {

	private String indication;
	private String subIndication;

	private XmlNode validationData;

	/**
	 * The {@code List} of information
	 */
	private List<Info> infoList;

	/**
	 * The {@code List} of warnings
	 */
	private List<Warning> warningList;

	/**
	 * The {@code List} of errors
	 */
	private List<Error> errorList;

	/**
	 * This class expresses an information.
	 */
	static public class Info extends BasicInfo {

		public Info() {
			super(NodeName.INFO);
		}

		public Info(final String value) {
			super(NodeName.INFO, value);
		}

		public Info(final String nameId, final String value) {
			super(nameId, NodeName.INFO, value);
		}

		public Info(final MessageTag messageTag) {
			super(NodeName.INFO, messageTag);
		}

		public Info(final MessageTag messageTag, final String... dynamicParameters) {
			super(NodeName.INFO, messageTag, dynamicParameters);
		}

		public Info(final MessageTag messageTag, final Map<String, String> attributes) {
			super(NodeName.INFO, messageTag, attributes);
		}
	}

	/**
	 * This class expresses a warning.
	 */
	static public class Warning extends BasicInfo {

		public Warning() {
			super(NodeName.WARNING);
		}

		public Warning(final String value) {
			super(NodeName.WARNING, value);
		}

		public Warning(final String nameId, final String value) {
			super(nameId, NodeName.WARNING, value);
		}

		public Warning(final MessageTag messageTag) {
			super(NodeName.WARNING, messageTag);
		}

		public Warning(final MessageTag messageTag, final Map<String, String> attributes) {
			super(NodeName.WARNING, messageTag, attributes);
		}
	}

	/**
	 * This class expresses a warning.
	 */
	static public class Error extends BasicInfo {

		public Error() {
			super(NodeName.ERROR);
		}

		public Error(String value) {
			super(NodeName.ERROR, value);
		}

		public Error(final String nameId, final String value) {
			super(nameId, NodeName.ERROR, value);
		}

		public Error(final MessageTag messageTag) {
			super(NodeName.ERROR, messageTag);
		}

		public Error(final MessageTag messageTag, final Map<String, String> attributes) {
			super(NodeName.ERROR, messageTag, attributes);
		}
	}

	/**
	 * This class contains information provided by the validation process and to be included in the conclusion.
	 */
	static public class BasicInfo {

		/**
		 * The tag to use to express the basic information: Info or Warning
		 */
		protected final String tag;

		/**
		 * The content of the basic information
		 */
		protected String value;

		/**
		 * The {@code HashMap} containing the node's attributes and their values.
		 */
		protected HashMap<String, String> attributes = new HashMap<String, String>();

		/**
		 * @param tag indicates the info type: Info or Warning
		 */
		protected BasicInfo(final String tag) {

			this.tag = tag;
		}

		public BasicInfo(final String tag, final String value) {

			this.tag = tag;
			this.value = value;
		}

		/**
		 * @param nameId indicates the unique message identifier
		 * @param tag    indicates the info type: Info or Warning
		 * @param value  the value of the information
		 */
		protected BasicInfo(final String nameId, final String tag, final String value) {

			setAttribute(AttributeName.NAME_ID, nameId);
			this.tag = tag;
			this.value = value;
		}

		/**
		 * @param tag        indicates the info type: Info or Warning
		 * @param messageTag indicates the unique message identifier
		 */
		protected BasicInfo(final String tag, final MessageTag messageTag) {

			setAttribute(AttributeName.NAME_ID, messageTag.name());
			this.tag = tag;
			this.value = messageTag.getMessage();
		}

		/**
		 * @param tag        indicates the info type: Info or Warning
		 * @param messageTag indicates the unique message identifier
		 */
		protected BasicInfo(final String tag, final MessageTag messageTag, final String... dynamicParameters) {

			setAttribute(AttributeName.NAME_ID, messageTag.name());
			this.tag = tag;
			final String message = String.format(messageTag.getMessage(), dynamicParameters);
			this.value = message;
		}

		/**
		 * @param tag        indicates the info type: Info or Warning
		 * @param messageTag indicates the unique message identifier
		 * @param attributes the value of the information
		 */
		protected BasicInfo(final String tag, final MessageTag messageTag, final Map<String, String> attributes) {

			setAttribute(AttributeName.NAME_ID, messageTag.name());
			this.tag = tag;
			this.value = messageTag.getMessage();
			if (attributes != null) {
				this.attributes.putAll(attributes);
			}
		}

		/**
		 * This method adds the given pair: attribute name, attribute value, to the {@code BasicInfo}. If the attribute exists already then its value is updated.
		 *
		 * @param name  attribute name
		 * @param value attribute value
		 * @return the instance of the current object
		 */
		public BasicInfo setAttribute(final String name, final String value) {

			attributes.put(name, value);
			return this;
		}

		public boolean hasAttribute(final String name) {

			return attributes.containsKey(name);
		}

		public boolean hasAttribute(final String name, final String value) {

			if (attributes.isEmpty()) {
				return false;
			}
			final String attributeValue = attributes.get(name);
			return (attributeValue != null) && attributeValue.equals(value);
		}

		public String getAttributeValue(final String name) {

			if (attributes.isEmpty()) {
				return null;
			}
			final String attributeValue = attributes.get(name);
			return attributeValue;
		}

		public String getValue() {
			return value;
		}

		public void setValue(final String value) {
			this.value = value;
		}

		/**
		 * This method adds the Info {@code XmlNode} to the given {@code XmlNode}
		 *
		 * @param xmlNode The node to which the Info node is added
		 */
		public void addTo(final XmlNode xmlNode) {

			final XmlNode info = xmlNode.addChild(NodeName.INFO, value);

			for (final Entry<String, String> entry : attributes.entrySet()) {

				info.setAttribute(entry.getKey(), entry.getValue());
			}
		}

		public HashMap<String, String> getAttributes() {
			return attributes;
		}


		@Override
		public String toString() {

			String attributeString = "";
			for (Entry<String, String> entry : attributes.entrySet()) {

				if ("NameId".equals(entry.getKey())) {
					continue;
				}
				attributeString += (attributeString.isEmpty() ? "" : ", ") + entry.getKey() + "=" + entry.getValue();
			}

			if (!value.isEmpty() && !attributeString.isEmpty()) {
				attributeString = " [" + attributeString + "]";

			}
			return value + (attributeString.isEmpty() ? "" : attributeString);
		}
	}

	public boolean isValid() {

		return Indication.VALID.equals(indication);
	}

	/**
	 * @return the indication returned by the validation process.
	 */
	public String getIndication() {
		return indication;
	}

	/**
	 * This method set the indication.
	 *
	 * @param indication to set
	 */
	public void setIndication(final String indication) {
		this.indication = indication;
	}

	/**
	 * @param indication    the indication to set
	 * @param subIndication the sub-indication to set
	 */
	public void setIndication(final String indication, final String subIndication) {
		this.indication = indication;
		this.subIndication = subIndication;
	}

	/**
	 * @return the sub-indication returned by the validation process
	 */
	public String getSubIndication() {
		return subIndication;
	}

	/**
	 * @param subIndication the sub-indication to set
	 */
	public void setSubIndication(final String subIndication) {
		this.subIndication = subIndication;
	}

	/**
	 * This method adds an {@code Info} to the information list.
	 *
	 * @return created {@code Info}
	 */
	public Info addInfo() {

		final Info info = new Info();
		ensureInfoList();
		infoList.add(info);
		return info;
	}

	/**
	 * This method adds an {@code Info} to the information list.
	 *
	 * @param messageTag {@code MessageTag} contains the unique message identifier and the content of the warning
	 * @return created {@code Info}
	 */
	public Info addInfo(final MessageTag messageTag) {

		final Info info = new Info(messageTag);
		ensureInfoList();
		infoList.add(info);
		return info;
	}

	/**
	 * This method adds an {@code Info} to the information list.
	 *
	 * @param messageTag {@code MessageTag} contains the unique message identifier and the content of the warning
	 * @return created {@code Info}
	 */
	public Info addInfo(final MessageTag messageTag, final String... dynamicParameters) {

		final Info info = new Info(messageTag, dynamicParameters);
		ensureInfoList();
		infoList.add(info);
		return info;
	}

	/**
	 * This method adds an {@code Info} to the information list.
	 *
	 * @param messageTag {@code MessageTag} contains the unique message identifier and the content of the warning
	 * @param attributes {@code Map} contains all attributes associated to the warning.
	 * @return created {@code Info}
	 */
	public Info addInfo(final MessageTag messageTag, Map<String, String> attributes) {

		final Info info = new Info(messageTag, attributes);
		ensureInfoList();
		infoList.add(info);
		return info;
	}

	/**
	 * Adds to this conclusion the information list contained in the {@code conclusion} parameter.
	 *
	 * @param conclusion from which the information list must be integrated to the current one.
	 */
	public void addInfo(final Conclusion conclusion) {

		if ((conclusion.infoList != null) && !conclusion.infoList.isEmpty()) {

			ensureInfoList();
			infoList.addAll(conclusion.infoList);
		}
	}

	/**
	 * This method adds the content of nodes contained in the given {@code List} of {@code XmlDom}(s) as information.
	 *
	 * @param infoList the {@code List} of {@code XmlDom}(s) to be integrated.
	 */
	public void addInfo(final List<XmlDom> infoList) {

		if ((infoList == null) || infoList.isEmpty()) {

			return;
		}
		ensureInfoList();
		for (final XmlDom xmlDom : infoList) {

			final String value = xmlDom.getText();
			final Info info = new Info(value);
			copyAttributes(xmlDom, info);
			this.infoList.add(info);
		}
	}

	private void copyAttributes(final XmlDom xmlDom, final BasicInfo basicInfo) {

		final NamedNodeMap attributes = xmlDom.getAttributes();
		for (int index = 0; index < attributes.getLength(); index++) {

			final Node attribute = attributes.item(index);
			final String attributeName = attribute.getNodeName();
			final String attributeValue = attribute.getNodeValue();
			basicInfo.setAttribute(attributeName, attributeValue);
		}
	}

	/**
	 * The children of the given {@code XmlNode} are added to the list of information.
	 *
	 * @param infoContainerXmlNode the {@code XmlNode} to integrate.
	 */
	public void addInfo(final XmlNode infoContainerXmlNode) {

		List<XmlNode> children;
		if ((infoContainerXmlNode == null) || (children = infoContainerXmlNode.getChildren()).isEmpty()) {

			return;
		}
		ensureInfoList();
		for (final XmlNode child : children) {

			final String value = child.getValue();
			final String messageId = DSSUtils.getMessageId(value);
			final Info info = new Info(messageId, value);
			final Map<String, String> attributes = child.getAttributes();
			for (final Entry<String, String> entry : attributes.entrySet()) {

				final String attributeName = entry.getKey();
				final String attributeValue = entry.getValue();
				info.setAttribute(attributeName, attributeValue);
			}
			infoList.add(info);
		}
	}

	public void copyBasicInfo(final XmlNode xmlNode) {

		if (xmlNode == null) {

			return;
		}
		final String name = xmlNode.getName();
		final String value = xmlNode.getValue();
		BasicInfo basicInfo = null;
		if (NodeName.ERROR.equals(name)) {

			basicInfo = addError();
		} else if (NodeName.WARNING.equals(name)) {

			basicInfo = addWarning();
		} else if (NodeName.INFO.equals(name)) {

			basicInfo = addInfo();

		}
		basicInfo.setValue(value);
		final Map<String, String> attributes = xmlNode.getAttributes();
		for (final Entry<String, String> entry : attributes.entrySet()) {

			basicInfo.setAttribute(entry.getKey(), entry.getValue());
		}
	}

	private BasicInfo addError() {

		final Error error = new Error();
		ensureErrorList();
		errorList.add(error);
		return error;
	}

	/**
	 * This method adds the content of nodes contained in the given {@code List} of {@code XmlDom}(s) as error.
	 *
	 * @param errors the {@code List} of {@code XmlDom}(s) to be integrated.
	 */
	private void addErrors(final List<XmlDom> errors) {

		if ((errors == null) || errors.isEmpty()) {

			return;
		}
		ensureErrorList();
		for (final XmlDom errorXmlDom : errors) {

			final String value = errorXmlDom.getText();
			final Error error = new Error(value);
			copyAttributes(errorXmlDom, error);
			errorList.add(error);
		}
	}

	private void ensureInfoList() {

		if (infoList == null) {
			infoList = new ArrayList<Info>();
		}
	}

	public Info getInfo(final String attributeName) {

		if (infoList == null) {
			return null;
		}
		for (Info info : infoList) {
			if (info.hasAttribute(attributeName)) {
				return info;
			}
		}
		return null;
	}

	public Info getInfo(final String attributeName, final String attributeValue) {

		if (infoList == null) {
			return null;
		}
		for (Info info : infoList) {
			if (info.hasAttribute(attributeName, attributeValue)) {
				return info;
			}
		}
		return null;
	}

	private BasicInfo addWarning() {

		final Warning warning = new Warning();
		ensureWarningList();
		warningList.add(warning);
		return warning;
	}

	/**
	 * This method adds an {@code Warning} to the warning list.
	 *
	 * @param messageTag {@code MessageTag} contains the unique message identifier and the content of the warning
	 * @param attributes {@code Map} contains all attributes associated to the warning.
	 * @return created {@code Warning}
	 */
	public Warning addWarning(final MessageTag messageTag, Map<String, String> attributes) {

		final Warning warning = new Warning(messageTag, attributes);
		ensureWarningList();
		warningList.add(warning);
		return warning;
	}

	/**
	 * This method adds an {@code Warning} to the warning list.
	 *
	 * @param messageTag {@code MessageTag} contains the unique message identifier and the content of the warning
	 * @return created {@code Warning}
	 */
	public Warning addWarning(final MessageTag messageTag) {

		final Warning warning = new Warning(messageTag);
		ensureWarningList();
		warningList.add(warning);
		return warning;
	}

	/**
	 * This method adds the content of nodes contained in the given {@code List} of {@code XmlDom}(s) as warning.
	 *
	 * @param warnings the {@code List} of {@code XmlDom}(s) to be integrated.
	 */
	private void addWarnings(List<XmlDom> warnings) {

		if ((warnings == null) || warnings.isEmpty()) {

			return;
		}
		ensureWarningList();
		for (final XmlDom warningXmlDom : warnings) {

			final String value = warningXmlDom.getText();
			final Warning warning = new Warning(value);
			copyAttributes(warningXmlDom, warning);
			warningList.add(warning);
		}
	}

	/**
	 * Adds to this conclusion the warning list contained in the {@code conclusion} parameter.
	 *
	 * @param conclusion from which the warning list must be integrated to the current one.
	 */
	public void addWarnings(final Conclusion conclusion) {

		if ((conclusion.warningList != null) && !conclusion.warningList.isEmpty()) {

			ensureWarningList();
			warningList.addAll(conclusion.warningList);
		}
	}

	private void ensureWarningList() {

		if (warningList == null) {
			warningList = new ArrayList<Warning>();
		}
	}

	/**
	 * This method adds an {@code Warning} to the warning list.
	 *
	 * @param messageTag {@code MessageTag} contains the unique message identifier and the content of the warning
	 * @return created {@code Warning}
	 */
	public Error addError(final MessageTag messageTag) {

		final Error error = new Error(messageTag);
		ensureErrorList();
		errorList.add(error);
		return error;
	}

	/**
	 * This method adds an {@code Error} to the error list.
	 *
	 * @param messageTag {@code MessageTag} contains the unique message identifier and the content of the error
	 * @param attributes {@code Map} contains all attributes associated to the error.
	 * @return created {@code Error}
	 */
	public Error addError(final MessageTag messageTag, Map<String, String> attributes) {

		final Error error = new Error(messageTag, attributes);
		ensureErrorList();
		errorList.add(error);
		return error;
	}

	private void ensureErrorList() {

		if (errorList == null) {
			errorList = new ArrayList<Error>();
		}
	}

	public XmlNode getValidationData() {

		return validationData;
	}

	/**
	 * This method sets the validation data (The Xml created during the validation process). The conclusion node is added based on the content of this object. This
	 * method must be called at the end of the process. If the content of this object changes, then this method need to
	 * be called again.
	 *
	 * @param validationData
	 */
	public void setValidationData(final XmlNode validationData) {

		validationData.addChild(this.toXmlNode());
		this.validationData = validationData;
	}

	/**
	 * This method creates {@code XmlNode} representing the conclusion of the validation process.
	 *
	 * @return {@code XmlNode} representing the conclusion of the validation process.
	 */
	public XmlNode toXmlNode() {

		final XmlNode conclusion = new XmlNode(NodeName.CONCLUSION);
		conclusion.addChild(NodeName.INDICATION, indication);
		if (subIndication != null) {

			conclusion.addChild(NodeName.SUB_INDICATION, subIndication);
		}
		infoToXmlNode(conclusion);
		warningToXmlNode(conclusion);
		errorToXmlNode(conclusion);
		return conclusion;
	}

	public void infoToXmlNode(final XmlNode conclusion) {

		basicInfoToXmlNode(infoList, NodeName.INFO, conclusion);
	}

	public void warningToXmlNode(final XmlNode conclusion) {

		basicInfoToXmlNode(warningList, NodeName.WARNING, conclusion);
	}

	public void errorToXmlNode(final XmlNode conclusion) {

		basicInfoToXmlNode(errorList, NodeName.ERROR, conclusion);
	}

	private void basicInfoToXmlNode(List<?> basicInfoList, final String infoLevel, final XmlNode conclusion) {

		if (basicInfoList != null) {

			for (final Object basicInfoObject : basicInfoList) {

				BasicInfo basicInfo = (BasicInfo) basicInfoObject;
				final XmlNode infoNode = conclusion.addChild(infoLevel, basicInfo.getValue());
				for (final Entry<String, String> entry : basicInfo.attributes.entrySet()) {

					infoNode.setAttribute(entry.getKey(), entry.getValue());
				}
			}
		}
	}

	public void copyConclusion(final XmlDom conclusionXmlDom) {

		final String indication = conclusionXmlDom.getValue("./Indication/text()");
		if (!indication.isEmpty()) {
			this.indication = indication;
		}

		final String subIndication = conclusionXmlDom.getValue("./SubIndication/text()");
		if (!subIndication.isEmpty()) {
			this.subIndication = subIndication;
		}

		final List<XmlDom> errors = conclusionXmlDom.getElements("./Error");
		addErrors(errors);

		final List<XmlDom> warnings = conclusionXmlDom.getElements("./Warning");
		addWarnings(warnings);

		final List<XmlDom> info = conclusionXmlDom.getElements("./Info");
		addInfo(info);
	}

	public void copyWarnings(final XmlDom conclusionXmlDom) {


		final List<XmlDom> warnings = conclusionXmlDom.getElements("./Warning");
		addWarnings(warnings);
	}

	@Override
	public String toString() {

		return toXmlNode().toString();
	}
}
