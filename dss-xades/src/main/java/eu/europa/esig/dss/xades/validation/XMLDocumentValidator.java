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

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidatorFactory;
import eu.europa.esig.dss.validation.policy.DefaultSignaturePolicyValidatorLoader;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidatorLoader;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureUtils;
import eu.europa.esig.dss.xades.validation.policy.XMLSignaturePolicyValidator;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xades.definition.XAdESPath;
import eu.europa.esig.xades.definition.xades111.XAdES111Path;
import eu.europa.esig.xades.definition.xades122.XAdES122Path;
import eu.europa.esig.xades.definition.xades132.XAdES132Path;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Validator of XML Signed document
 *
 */
public class XMLDocumentValidator extends SignedDocumentValidator {

	/**
	 * This variable contains the list of {@code XAdESPaths} adapted to the specific
	 * signature schema.
	 */
	protected List<XAdESPath> xadesPathsHolders;

	/** The root element of the document to validate */
	protected Document rootElement;

	/** Defines if the XSW protection shall be disabled (false by default) */
	private boolean disableXSWProtection = false;

	static {
		DSSXMLUtils.registerXAdESNamespaces();
	}

	/**
	 * Default constructor
	 */
	XMLDocumentValidator() {
		// empty
	}

	/**
	 * The default constructor for XMLDocumentValidator. The created instance is
	 * initialised with default {@code XAdESPaths} .
	 *
	 * @param dssDocument
	 *                    The instance of {@code DSSDocument} to validate
	 */
	public XMLDocumentValidator(final DSSDocument dssDocument) {
		Objects.requireNonNull(dssDocument, "Document to be validated cannot be null!");

		this.document = dssDocument;
		this.rootElement = toDomDocument(dssDocument);

		xadesPathsHolders = new ArrayList<>();
		xadesPathsHolders.add(new XAdES111Path());
		xadesPathsHolders.add(new XAdES122Path());
		xadesPathsHolders.add(new XAdES132Path());
	}

	private Document toDomDocument(DSSDocument document) {
		try {
			return DomUtils.buildDOM(document);
		} catch (Exception e) {
			throw new IllegalInputException(String.format("An XML file is expected : %s", e.getMessage()), e);
		}
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		return DomUtils.startsWithXmlPreamble(dssDocument) && !EvidenceRecordValidatorFactory.isSupportedDocument(dssDocument);
	}

	/**
	 * NOT RECOMMENDED : This parameter allows disabling protection against XML
	 * Signature wrapping attacks (XSW). It disables the research by XPath
	 * expression for defined Type attributes.
	 * 
	 * @param disableXSWProtection
	 *                             true to disable the protection
	 */
	public void setDisableXSWProtection(boolean disableXSWProtection) {
		this.disableXSWProtection = disableXSWProtection;
	}

	@Override
	protected List<AdvancedSignature> buildSignatures() {
		List<AdvancedSignature> signatures = new ArrayList<>();
		final NodeList signatureNodeList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(rootElement);
		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			final Element signatureEl = (Element) signatureNodeList.item(ii);
			final Node parent = signatureEl.getParentNode();
			final String nodeName = parent.getNodeName();
			final String ns = parent.getNamespaceURI();
			
			if ("saml2:Assertion".equals(nodeName) && DSSXMLUtils.SAML_NAMESPACE.isSameUri(ns)) {
				continue; // skip signed assertions
			}

			final XAdESSignature xadesSignature = new XAdESSignature(signatureEl, xadesPathsHolders);
			xadesSignature.setSignatureFilename(document.getName());
			xadesSignature.setDetachedContents(detachedContents);
			xadesSignature.setContainerContents(containerContents);
			xadesSignature.setSigningCertificateSource(signingCertificateSource);
			xadesSignature.setDisableXSWProtection(disableXSWProtection);
			xadesSignature.prepareOfflineCertificateVerifier(certificateVerifier);
			signatures.add(xadesSignature);
		}
		return signatures;
	}
	
	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		XAdESSignature signature = (XAdESSignature) advancedSignature;
		return XAdESSignatureUtils.getSignerDocuments(signature);
	}

	/**
	 * This getter returns the {@code XAdESPaths}
	 *
	 * @return a list of {@link XAdESPath}
	 */
	public List<XAdESPath> getXAdESPathsHolder() {
		return xadesPathsHolders;
	}

	/**
	 * This adds a {@code XAdESPaths}. This is useful when the signature follows a
	 * particular schema.
	 *
	 * @param xadesPathsHolder {@link XAdESPath}
	 */
	public void addXAdESPathsHolder(final XAdESPath xadesPathsHolder) {
		xadesPathsHolders.add(xadesPathsHolder);
	}

	/**
	 * Removes all elements from the list of query holders. The list will be empty after this call returns.
	 */
	public void clearQueryHolders() {
		xadesPathsHolders.clear();
	}

	/**
	 * Returns the root element of the validating document
	 *
	 * @return {@link Document}
	 */
	public Document getRootElement() {
		return rootElement;
	}

	@Override
	public SignaturePolicyValidatorLoader getSignaturePolicyValidatorLoader() {
		DefaultSignaturePolicyValidatorLoader signaturePolicyValidatorLoader = new DefaultSignaturePolicyValidatorLoader();
		signaturePolicyValidatorLoader.setDefaultSignaturePolicyValidator(new XMLSignaturePolicyValidator());
		return signaturePolicyValidatorLoader;
	}

}
