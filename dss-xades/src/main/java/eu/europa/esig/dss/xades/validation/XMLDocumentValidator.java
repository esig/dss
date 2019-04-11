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
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;

/**
 * Validator of XML Signed document
 *
 */
public class XMLDocumentValidator extends SignedDocumentValidator {

	private static final byte[] xmlPreamble = new byte[] { '<', '?', 'x', 'm', 'l' };
	private static final byte[] xmlUtf8 = new byte[] { -17, -69, -65, '<', '?' };

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
	 */
	public XMLDocumentValidator(final DSSDocument dssDocument) {

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
		final MimeType documentMimeType = dssDocument.getMimeType();
		if ((documentMimeType != null) && MimeType.XML.equals(documentMimeType)) {
			return true;
		}
		final String dssDocumentName = dssDocument.getName();
		if ((dssDocumentName != null) && MimeType.XML.equals(MimeType.fromFileName(dssDocumentName))) {
			return true;
		}
		int headerLength = xmlPreamble.length;
		byte[] preamble = new byte[headerLength];
		DSSUtils.readToArray(dssDocument, headerLength, preamble);
		return Arrays.equals(preamble, xmlPreamble) || Arrays.equals(preamble, xmlUtf8);
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

		final NodeList signatureNodeList = rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, XPathQueryHolder.XMLE_SIGNATURE);
		List<AdvancedSignature> signatureList = getSignatures();

		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {
			final Element signatureEl = (Element) signatureNodeList.item(ii);
			final String idIdentifier = DSSXMLUtils.getIDIdentifier(signatureEl);
			if (signatureId.equals(idIdentifier)) {
				return getOriginalDocuments(signatureList.get(ii));
			}
		}
		return Collections.emptyList();
	}
	
	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) throws DSSException {
		XAdESSignature signature = (XAdESSignature) advancedSignature;
		return XAdESUtils.getSignerDocuments(signature);
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
