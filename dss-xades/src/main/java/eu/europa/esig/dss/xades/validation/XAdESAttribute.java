package eu.europa.esig.dss.xades.validation;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.validation.timestamp.ISignatureAttribute;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.xades.XPathQueryHolder;

public class XAdESAttribute implements ISignatureAttribute {
	
	private final Element element;
	private final XPathQueryHolder xPathQueryHolder;
	
	private String localName;
	
	XAdESAttribute(Element element, XPathQueryHolder xPathQueryHolder) {
		this.element = element;
		this.xPathQueryHolder = xPathQueryHolder;
	}
	
	/**
	 * Returns the local name of the element
	 * @return {@link String} attribute's name
	 */
	public String getName() {
		if (localName == null) {
			localName = element.getLocalName();
		}
		return localName;
	}
	
	/**
	 * Returns namespae of the element
	 * @return {@link String} namespace
	 */
	public String getNamespace() {
		return element.getNamespaceURI();
	}
	
	/**
	 * Returns an inner {@link Element} found by the given {@code xPathExpression}
	 * @param xPathExpression {@link String} to find an element
	 */
	public final Element findElement(String xPathExpression) {
		return DomUtils.getElement(element, xPathExpression);
	}

	/**
	 * Returns a {@link NodeList} found by the given {@code xPathExpression}
	 * @param xPathExpression {@link String} to find an element
	 */
	public final NodeList getNodeList(String xPathExpression) {
		return DomUtils.getNodeList(element, xPathExpression);
	}

	/**
	 * Returns TimeStamp Canonicalization Method
	 * @return {@link String} timestamp canonicalization mathod
	 */
	public String getTimestampCanonicalizationMethod() {
		final Element canonicalizationMethodElement = DomUtils.getElement(element, xPathQueryHolder.XPATH__CANONICALIZATION_METHOD);
		if (canonicalizationMethodElement != null) {
			return canonicalizationMethodElement.getAttribute(XPathQueryHolder.XMLE_ALGORITHM);
		}
		return null;
	}
	
	/**
	 * Returns a list of {@link TimestampInclude}d refereces in case of IndividualDataObjectsTimestamp,
	 * NULL if does not contain any includes
	 * @return list of {@link TimestampInclude}s in case of IndividualDataObjectsTimestamp, NULL otherwise
	 */
	public List<TimestampInclude> getTimestampIncludedReferences() {
		final NodeList timestampIncludes = DomUtils.getNodeList(element, xPathQueryHolder.XPATH__INCLUDE);
		if (timestampIncludes != null && timestampIncludes.getLength() > 0) {
			List<TimestampInclude> includes = new ArrayList<TimestampInclude>();
			for (int jj = 0; jj < timestampIncludes.getLength(); jj++) {
				final Element include = (Element) timestampIncludes.item(jj);
				final String uri = DomUtils.getId(include.getAttribute("URI"));
				final String referencedData = include.getAttribute("referencedData");
				includes.add(new TimestampInclude(uri, Boolean.parseBoolean(referencedData)));
			}
			return includes;
		}
		return null;
	}
	
	public int getElementHashCode() {
		return element.hashCode();
	}
	
	@Override
	public String toString() {
		return getName();
	}

}
