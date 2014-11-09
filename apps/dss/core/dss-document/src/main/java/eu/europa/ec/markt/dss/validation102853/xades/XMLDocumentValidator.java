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

package eu.europa.ec.markt.dss.validation102853.xades;

import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.scope.SignatureScopeFinder;
import eu.europa.ec.markt.dss.validation102853.scope.SignatureScopeFinderFactory;

/**
 * Validator of XML Signed document
 *
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class XMLDocumentValidator extends SignedDocumentValidator {

	/**
	 * This variable contains the list of {@code XPathQueryHolder} adapted to the specific signature schema.
	 */
	protected List<XPathQueryHolder> xPathQueryHolders;

	protected Document rootElement;

	/**
	 * The default constructor for XMLDocumentValidator. The created instance is initialised with default {@code XPathQueryHolder} and {@code XAdES111XPathQueryHolder}.
	 *
	 * @param dssDocument The instance of {@code DSSDocument} to validate
	 * @throws DSSException
	 */
	public XMLDocumentValidator(final DSSDocument dssDocument) throws DSSException {

		xadesSignatureScopeFinder = SignatureScopeFinderFactory.geInstance(XAdESSignature.class);
		this.document = dssDocument;
		this.rootElement = DSSXMLUtils.buildDOM(dssDocument);

		xPathQueryHolders = new ArrayList<XPathQueryHolder>();

		final XAdES111XPathQueryHolder xades111xPathQueryHolder = new XAdES111XPathQueryHolder();
		xPathQueryHolders.add(xades111xPathQueryHolder);

		final XPathQueryHolder xades122XPathQueryHolder = new XAdES122XPathQueryHolder();
		xPathQueryHolders.add(xades122XPathQueryHolder);

		final XPathQueryHolder xPathQueryHolder = new XPathQueryHolder();
		xPathQueryHolders.add(xPathQueryHolder);
	}

	@Override
	public List<AdvancedSignature> getSignatures() {

		if (signatures != null) {
			return signatures;
		}
		signatures = new ArrayList<AdvancedSignature>();
		final NodeList signatureNodeList = DSSXMLUtils.getNodeList(rootElement, "//ds:Signature[not(parent::xades:CounterSignature)]");
		//final NodeList signatureNodeList = rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, XPathQueryHolder.XMLE_SIGNATURE);
		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			final Element signatureEl = (Element) signatureNodeList.item(ii);
			final XAdESSignature xadesSignature = new XAdESSignature(signatureEl, xPathQueryHolders, validationCertPool);
			xadesSignature.setDetachedContents(detachedContents);
			xadesSignature.setProvidedSigningCertificateToken(providedSigningCertificateToken);
			signatures.add(xadesSignature);
		}
		return signatures;
	}

	/**
	 * Retrieves a signature based on its Id
	 *
	 * @param signatureId the given Id
	 * @return the corresponding {@code XAdESSignature}
	 * @throws DSSException in case no Id is provided, or in case no signature was found for the given Id
	 */
	public AdvancedSignature getSignatureById(final String signatureId) throws DSSException {

		if (DSSUtils.isBlank(signatureId)) {
			throw new DSSNullException(String.class, "signatureId");
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
	public DSSDocument removeSignature(final String signatureId) throws DSSException {

		if (DSSUtils.isBlank(signatureId)) {
			throw new DSSNullException(String.class, "signatureId");
		}
		// TODO (31/07/2014): Checks on signature packaging to be added
		final NodeList signatureNodeList = rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, XPathQueryHolder.XMLE_SIGNATURE);
		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			final Element signatureEl = (Element) signatureNodeList.item(ii);
			final String idIdentifier = DSSXMLUtils.getIDIdentifier(signatureEl);
			if (signatureId.equals(idIdentifier)) {

				signatureEl.getParentNode().removeChild(signatureEl);
				// TODO (31/07/2014): Save the modified document
				final Node documentElement = rootElement.getDocumentElement();
				final byte[] documentBytes = DSSXMLUtils.serializeNode(documentElement);
				final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
				return inMemoryDocument;
			}
		}
		throw new DSSException("The signature with the given id was not found!");
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

	@Override
	protected SignatureScopeFinder getSignatureScopeFinder() {
		return xadesSignatureScopeFinder;
	}

	/**
	 * @return
	 */
	public Document getRootElement() {
		return rootElement;
	}
}
