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
package eu.europa.esig.dss;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * This class encapsulates an org.w3c.dom.Document. Its integrates the ability to execute XPath queries on XML
 * documents.
 */
public class XmlDom {

	private static final Logger LOG = LoggerFactory.getLogger(XmlDom.class);

	public static final String NAMESPACE = "http://dss.esig.europa.eu/validation/diagnostic";

	private static final String NS_PREFIX = "dss";

	private static final XPathFactory factory = XPathFactory.newInstance();

	private static final NamespaceContextMap nsContext;

	private static final Map<String, String> namespaces;

	static {

		namespaces = new HashMap<String, String>();
		namespaces.put(NS_PREFIX, NAMESPACE);
		nsContext = new NamespaceContextMap();
		nsContext.registerNamespace(NS_PREFIX, NAMESPACE);
	}

	public final Element rootElement;

	String nameSpace;

	public XmlDom(final Document document) {

		this.rootElement = document.getDocumentElement();
		nameSpace = rootElement.getNamespaceURI();
	}

	public XmlDom(final Element element) {

		this.rootElement = element;
	}

	private static XPathExpression createXPathExpression(final String xpathString) {

		final XPath xpath = factory.newXPath();
		xpath.setNamespaceContext(nsContext);
		try {

			final XPathExpression expr = xpath.compile(xpathString);
			return expr;
		} catch (XPathExpressionException ex) {

			throw new RuntimeException(ex);
		}
	}

	private static NodeList getNodeList(final Node xmlNode, final String xpathString) {

		try {

			final XPathExpression expr = createXPathExpression(xpathString);
			return (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
		} catch (XPathExpressionException e) {

			throw new RuntimeException(e);
		}
	}

	/**
	 * The list of elements corresponding the given XPath query and parameters.
	 *
	 * @param xPath
	 * @param params
	 * @return
	 */
	public List<XmlDom> getElements(final String xPath, final Object... params) {

		try {

			String xPath_ = format(xPath, params);

			NodeList nodeList = getNodeList(rootElement, xPath_);
			List<XmlDom> list = new ArrayList<XmlDom>();
			for (int ii = 0; ii < nodeList.getLength(); ii++) {

				Node node = nodeList.item(ii);
				if ((node != null) && (node.getNodeType() == Node.ELEMENT_NODE)) {

					list.add(new XmlDom((Element) node));
				}
			}
			return list;
		} catch (Exception e) {

			String message = "XPath error: '" + xPath + "'.";
			throw new DSSException(message, e);
		}
	}

	public XmlDom getElement(final String xPath, final Object... params) {

		try {

			String xPath_ = format(xPath, params);

			NodeList nodeList = getNodeList(rootElement, xPath_);
			for (int ii = 0; ii < nodeList.getLength(); ii++) {

				Node node = nodeList.item(ii);
				if ((node != null) && (node.getNodeType() == Node.ELEMENT_NODE)) {

					return new XmlDom((Element) node);
				}
			}
			return null;
		} catch (Exception e) {

			String message = "XPath error: '" + xPath + "'.";
			throw new DSSException(message, e);
		}
	}

	/**
	 * @param xPath
	 * @param params
	 * @return
	 */
	private static String format(final String xPath, final Object... params) {

		String formattedXPath;
		if (params.length > 0) {

			formattedXPath = String.format(xPath, params);
		} else {

			formattedXPath = xPath;
		}
		formattedXPath = addNamespacePrefix(formattedXPath);
		return formattedXPath;
	}

	private static String addNamespacePrefix(final String formatedXPath) {

		if (formatedXPath.startsWith("/dss:") || formatedXPath.startsWith("./dss:")) {

			// Already formated.
			return formatedXPath;
		}
		String formatedXPath_ = formatedXPath;
		CharSequence from = "//";
		CharSequence to = "{#double}/";
		boolean special = formatedXPath_.indexOf("//") != -1;
		if (special) {
			formatedXPath_ = formatedXPath_.replace(from, to);
		}
		StringTokenizer tokenizer = new StringTokenizer(formatedXPath_, "/");

		StringBuilder stringBuilder = new StringBuilder();

		while (tokenizer.hasMoreTokens())

		{

			String token = tokenizer.nextToken();

			final boolean isDot = ".".equals(token);
			final boolean isCount = "count(".equals(token) || "count(.".equals(token);
			final boolean isDoubleDot = "..".equals(token);
			final boolean isAt = token.startsWith("@");
			final boolean isText = token.equals("text()");
			final boolean isDoubleSlash = token.equals("{#double}");
			final String slash = isDot || isCount || isDoubleSlash ? "" : "/";
			String prefix = isDot || isCount || isDoubleDot || isAt || isText || isDoubleSlash ? "" : "dss:";

			stringBuilder.append(slash).append(prefix).append(token);
		}

		String normalizedXPath = stringBuilder.toString();
		if (special) {
			normalizedXPath = normalizedXPath.replace(to, from);
		}
		return normalizedXPath;
	}

	/**
	 * This method never returns null.
	 *
	 * @param xPath
	 * @param params
	 * @return {@code String} value or empty string
	 */
	public String getValue(final String xPath, final Object... params) {

		String xPath_ = format(xPath, params);

		NodeList nodeList = getNodeList(rootElement, xPath_);
		if (nodeList.getLength() == 1) {
			Node node = nodeList.item(0);
			if (node.getNodeType() != Node.ELEMENT_NODE) {
				String value = nodeList.item(0).getTextContent();
				return value.trim();
			}
		}
		return "";
	}

	public int getIntValue(final String xPath, final Object... params) {

		String value = getValue(xPath, params);
		try {

			return Integer.parseInt(value);
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	public long getLongValue(final String xPath, final Object... params) {

		String value = getValue(xPath, params);
		try {

			value = value.trim();
			return Long.parseLong(value);
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	public boolean getBoolValue(final String xPath, final Object... params) {

		String value = getValue(xPath, params);
		if (value.equals("true")) {
			return true;

		} else if (value.isEmpty() || value.equals("false")) {

			return false;
		}
		throw new DSSException("Expected values are: true, false and not '" + value + "'.");
	}

	public long getCountValue(final String xPath, final Object... params) {

		String xpathString = format(xPath, params);
		try {

			XPathExpression xPathExpression = createXPathExpression(xpathString);
			Double number = (Double) xPathExpression.evaluate(rootElement, XPathConstants.NUMBER);
			return number.intValue();
		} catch (XPathExpressionException e) {

			throw new RuntimeException(e);
		}
	}

	public boolean exists(final String xPath, final Object... params) {

		XmlDom element = getElement(xPath, params);
		return element != null;
	}

	public Date getTimeValue(final String xPath, final Object... params) {

		String value = getValue(xPath, params);
		return DSSUtils.parseDate(value);
	}

	public Date getTimeValueOrNull(final String xPath, final Object... params) {

		String value = getValue(xPath, params);
		if (value.isEmpty()) {
			return null;
		}
		return DSSUtils.parseDate(value);
	}

	public String getText() {

		try {
			if (rootElement != null) {

				return rootElement.getTextContent().trim();
			}
		} catch (Exception e) {
		}
		return null;
	}

	/**
	 * The name of this node, depending on its type;
	 *
	 * @return
	 */
	public String getName() {

		return rootElement.getNodeName();
	}

	/**
	 * Retrieves an attribute value by name.
	 *
	 * @param attributeName
	 * @return
	 */
	public String getAttribute(final String attributeName) {

		return rootElement.getAttribute(attributeName);
	}

	/**
	 * Retrieves an attribute value by name.
	 *
	 * @return
	 */
	public NamedNodeMap getAttributes() {

		return rootElement.getAttributes();
	}

	/**
	 * Converts the list of {@code XmlDom} to {@code List} of {@code String}. The children of the node are not taken
	 * into account.
	 *
	 * @param xmlDomList the list of {@code XmlDom} to convert
	 * @return converted {@code List} of {@code String}.
	 */
	public static List<String> convertToStringList(final List<XmlDom> xmlDomList) {

		final List<String> stringList = new ArrayList<String>();
		for (final XmlDom xmlDom : xmlDomList) {

			stringList.add(xmlDom.getText());
		}
		return stringList;
	}

	/**
	 * Converts the list of {@code XmlDom} to {@code Map} of {@code String}, {@code String}. The children of the node are not taken
	 * into account.
	 *
	 * @param xmlDomList    the list of {@code XmlDom} to convert
	 * @param attributeName the name of the attribute to use as value
	 * @return converted {@code Map} of {@code String}, {@code String} corresponding to the element content and the attribute value.
	 */
	public static Map<String, String> convertToStringMap(final List<XmlDom> xmlDomList, final String attributeName) {

		final Map<String, String> stringMap = new HashMap<String, String>();
		for (final XmlDom xmlDom : xmlDomList) {

			final String key = xmlDom.getText();
			final String value = xmlDom.getAttribute(attributeName);
			stringMap.put(key, value);
		}
		return stringMap;
	}

	/**
	 * Converts the list of {@code XmlDom} to {@code Map} of {@code String}, {@code Date}. The children of the node are not taken
	 * into account. If a problem is encountered during the conversion the pair key, value is ignored and a warning is logged.
	 *
	 * @param xmlDomList    the list of {@code XmlDom} to convert
	 * @param attributeName the name of the attribute to use as value
	 * @return converted {@code Map} of {@code String}, {@code Date} corresponding to the element content and the attribute value.
	 */
	public static Map<String, Date> convertToStringDateMap(final List<XmlDom> xmlDomList, final String attributeName) {

		final Map<String, Date> stringMap = new HashMap<String, Date>();
		for (final XmlDom xmlDom : xmlDomList) {

			final String key = xmlDom.getText();
			final String dateString = xmlDom.getAttribute(attributeName);
			String format = xmlDom.getAttribute("Format");
			if (StringUtils.isBlank(format)) {
				format = "yyyy-MM-dd";
			}
			if (StringUtils.isBlank(dateString)) {

				LOG.warn(String.format("The date is not defined for key '%s'!", key));
				continue;
			}
			final Date date;
			try {
				date = DSSUtils.parseDate(format, dateString);
			} catch (DSSException e) {

				LOG.warn("The date conversion is not possible.", e);
				continue;
			}
			stringMap.put(key, date);
		}
		return stringMap;
	}

	public byte[] toByteArray() {

		if (rootElement != null) {

			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			printDocument(rootElement, byteArrayOutputStream, false);
			return byteArrayOutputStream.toByteArray();
		}
		return DSSUtils.EMPTY_BYTE_ARRAY;
	}

	@Override
	public String toString() {

		if (rootElement != null) {

			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			printDocument(rootElement, byteArrayOutputStream, false);
			return getUtf8String(byteArrayOutputStream.toByteArray());
		}
		return super.toString();
	}


	/**
	 * Constructs a new <code>String</code> by decoding the specified array of bytes using the UTF-8 charset.
	 *
	 * @param bytes The bytes to be decoded into characters
	 * @return A new <code>String</code> decoded from the specified array of bytes using the UTF-8 charset,
	 * or <code>null</code> if the input byte array was <code>null</code>.
	 * @throws IllegalStateException Thrown when a {@link UnsupportedEncodingException} is caught, which should never happen since the
	 *                               charset is required.
	 */
	private static String getUtf8String(byte[] bytes) {

		if (bytes == null) {
			return null;
		}
		try {
			return new String(bytes, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method writes formatted {@link org.w3c.dom.Node} to the outputStream.
	 *
	 * @param node
	 * @param out
	 */
	private static void printDocument(final Node node, final OutputStream out, final boolean raw) {

		try {

			final TransformerFactory tf = TransformerFactory.newInstance();
			final Transformer transformer = tf.newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			if (!raw) {

				transformer.setOutputProperty(OutputKeys.INDENT, "yes");
				transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "3");
			}
			transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

			final DOMSource xmlSource = new DOMSource(node);
			final OutputStreamWriter writer = new OutputStreamWriter(out, "UTF-8");
			final StreamResult outputTarget = new StreamResult(writer);
			transformer.transform(xmlSource, outputTarget);
		} catch (Exception e) {
			throw new DSSException(e);
		}

	}

	public Element getRootElement() {
		return rootElement;
	}
}
