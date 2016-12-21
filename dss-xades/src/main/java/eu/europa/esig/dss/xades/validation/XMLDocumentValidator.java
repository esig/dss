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
package eu.europa.esig.dss.xades.validation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.crypto.dsig.XMLSignature;

import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * Validator of XML Signed document
 *
 */
public class XMLDocumentValidator extends SignedDocumentValidator {

	private static final byte[] xmlPreamble = new byte[] { '<', '?', 'x', 'm', 'l' };
	private static final byte[] xmlUtf8 = new byte[] { -17, -69, -65, '<', '?' };
	private static final String BASE64_REGEX = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";

	/**
	 * This variable contains the list of {@code XPathQueryHolder} adapted to the specific signature schema.
	 */
	protected List<XPathQueryHolder> xPathQueryHolders;

	protected Document rootElement;

	private List<AdvancedSignature> signatures;

	/**
	 * Default constructor used with reflexion (see SignedDocumentValidator)
	 */
	private XMLDocumentValidator() {
		super(null);
	}

	/**
	 * The default constructor for XMLDocumentValidator. The created instance is initialised with default
	 * {@code XPathQueryHolder} and
	 * {@code XAdES111XPathQueryHolder}.
	 *
	 * @param dssDocument
	 *            The instance of {@code DSSDocument} to validate
	 * @throws DSSException
	 */
	public XMLDocumentValidator(final DSSDocument dssDocument) throws DSSException {

		super(new XAdESSignatureScopeFinder());
		this.document = dssDocument;
		this.rootElement = DomUtils.buildDOM(dssDocument);

		xPathQueryHolders = new ArrayList<XPathQueryHolder>();

		final XAdES111XPathQueryHolder xades111xPathQueryHolder = new XAdES111XPathQueryHolder();
		xPathQueryHolders.add(xades111xPathQueryHolder);

		final XPathQueryHolder xades122XPathQueryHolder = new XAdES122XPathQueryHolder();
		xPathQueryHolders.add(xades122XPathQueryHolder);

		final XPathQueryHolder xPathQueryHolder = new XPathQueryHolder();
		xPathQueryHolders.add(xPathQueryHolder);
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		final String dssDocumentName = dssDocument.getName();
		if ((dssDocumentName != null) && MimeType.XML.equals(MimeType.fromFileName(dssDocumentName))) {
			return true;
		}
		int headerLength = 500;
		byte[] preamble = new byte[headerLength];
		DSSUtils.readToArray(dssDocument, headerLength, preamble);
		if (isXmlPreamble(preamble)) {
			return true;
		}
		return false;
	}

	private boolean isXmlPreamble(byte[] preamble) {
		byte[] startOfPramble = Utils.subarray(preamble, 0, xmlPreamble.length);
		return Arrays.equals(startOfPramble, xmlPreamble) || Arrays.equals(startOfPramble, xmlUtf8);
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		if (signatures != null) {
			return signatures;
		}

		signatures = new ArrayList<AdvancedSignature>();
		final NodeList signatureNodeList = DomUtils.getNodeList(rootElement, "//ds:Signature[not(parent::xades:CounterSignature)]");
		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			final Element signatureEl = (Element) signatureNodeList.item(ii);
			final XAdESSignature xadesSignature = new XAdESSignature(signatureEl, xPathQueryHolders, validationCertPool);
			xadesSignature.setSignatureFilename(document.getName());
			xadesSignature.setDetachedContents(detachedContents);
			xadesSignature.setProvidedSigningCertificateToken(providedSigningCertificateToken);
			signatures.add(xadesSignature);
		}
		return signatures;
	}

	/**
	 * Retrieves a signature based on its Id
	 *
	 * @param signatureId
	 *            the given Id
	 * @return the corresponding {@code XAdESSignature}
	 * @throws DSSException
	 *             in case no Id is provided, or in case no signature was found for the given Id
	 */
	public AdvancedSignature getSignatureById(final String signatureId) throws DSSException {

		if (Utils.isStringBlank(signatureId)) {
			throw new NullPointerException("signatureId");
		}
		final List<AdvancedSignature> advancedSignatures = getSignatures();
		for (final AdvancedSignature advancedSignature : advancedSignatures) {

			final String advancedSignatureId = advancedSignature.getId();
			if (signatureId.equals(advancedSignatureId)) {
				return advancedSignature;
			}
		}
		throw new DSSException("The signature with the given id was not found!");
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(final String signatureId) throws DSSException {

		if (Utils.isStringBlank(signatureId)) {
			throw new NullPointerException("signatureId");
		}

		List<DSSDocument> result = new ArrayList<DSSDocument>();

		final NodeList signatureNodeList = rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, XPathQueryHolder.XMLE_SIGNATURE);
		List<AdvancedSignature> signatureList = getSignatures();

		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			final Element signatureEl = (Element) signatureNodeList.item(ii);
			final String idIdentifier = DSSXMLUtils.getIDIdentifier(signatureEl);

			if (signatureId.equals(idIdentifier)) {
				XAdESSignature signature = (XAdESSignature) signatureList.get(ii);
				signature.checkSignatureIntegrity();
				if (getSignatureObjects(signatureEl).isEmpty() && signature.getReferences().isEmpty()) {
					throw new DSSException("The signature must be enveloped or enveloping!");
				} else if (isEnveloping(signatureEl)) {
					List<Element> references = getSignatureObjects(signatureEl);
					for (Element element : references) {
						String content = element.getTextContent();
						content = isBase64Encoded(content) ? new String(Base64.decode(content)) : content;
						result.add(new InMemoryDocument(content.getBytes()));
					}
				} else {
					signatureEl.getParentNode().removeChild(signatureEl);
					final Node documentElement = rootElement.getDocumentElement();
					byte[] documentBytes = DSSXMLUtils.serializeNode(documentElement);
					documentBytes = isBase64Encoded(documentBytes) ? Base64.decode(documentBytes) : documentBytes;
					result.add(new InMemoryDocument(documentBytes));
				}
			}
		}
		return result;
	}

	private boolean isBase64Encoded(byte[] array) {
		return isBase64Encoded(new String(array));
	}

	private boolean isBase64Encoded(String text) {
		Pattern pattern = Pattern.compile(BASE64_REGEX);
		Matcher matcher = pattern.matcher(text);
		return matcher.matches();
	}

	private boolean isEnveloping(Element signatureEl) {
		final NodeList objectNodeList = signatureEl.getChildNodes();
		int objectTagNumber = 0;
		for (int i = 0; i < objectNodeList.getLength(); i++) {
			String nodeName = objectNodeList.item(i).getNodeName();
			if ("ds:Object".equals(nodeName)) {
				objectTagNumber++;
			}
		}
		return objectTagNumber >= 2;
	}

	private List<Element> getSignatureObjects(Element signatureEl) {

		final NodeList list = DomUtils.getNodeList(signatureEl, XPathQueryHolder.XPATH_OBJECT);
		final List<Element> references = new ArrayList<Element>(list.getLength());
		for (int ii = 0; ii < list.getLength(); ii++) {
			final Node node = list.item(ii);
			final Element element = (Element) node;
			XPathQueryHolder queryHolder = new XPathQueryHolder();
			if (DomUtils.getElement(element, queryHolder.XPATH__QUALIFYING_PROPERTIES_SIGNED_PROPERTIES) != null) {
				// ignore signed properties
				continue;
			}
			references.add(element);
		}
		return references;
	}

	/**
	 * This getter returns the {@code XPathQueryHolder}
	 *
	 * @return
	 */
	public List<XPathQueryHolder> getXPathQueryHolder() {
		return xPathQueryHolders;
	}

	/**
	 * This adds a {@code XPathQueryHolder}. This is useful when the signature follows a particular schema.
	 *
	 * @param xPathQueryHolder
	 */
	public void addXPathQueryHolder(final XPathQueryHolder xPathQueryHolder) {

		xPathQueryHolders.add(xPathQueryHolder);
	}

	/**
	 * Removes all of the elements from the list of query holders. The list will be empty after this call returns.
	 */
	public void clearQueryHolders() {
		xPathQueryHolders.clear();
	}

	/**
	 * @return
	 */
	public Document getRootElement() {
		return rootElement;
	}

}
