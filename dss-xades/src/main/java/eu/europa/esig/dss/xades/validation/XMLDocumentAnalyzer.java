/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.policy.SignaturePolicyValidator;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzerFactory;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureUtils;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import eu.europa.esig.dss.xades.definition.xades111.XAdES111Path;
import eu.europa.esig.dss.xades.definition.xades122.XAdES122Path;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xades.dom.XAdESDOMDocument;
import eu.europa.esig.dss.xades.dom.XAdESDOMElement;
import eu.europa.esig.dss.xades.validation.policy.XMLSignaturePolicyValidator;
import eu.europa.esig.dss.xml.utils.DomUtils;
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
public class XMLDocumentAnalyzer extends DefaultDocumentAnalyzer {

	/** The document to validate */
	protected XAdESDOMDocument domDocument;

	/** Defines if the XSW protection shall be disabled (false by default) */
	private boolean disableXSWProtection = false;

	static {
		DSSXMLUtils.registerXAdESNamespaces();
	}

	/**
	 * Default constructor
	 */
	XMLDocumentAnalyzer() {
		// empty
	}

	/**
	 * The default constructor for XMLDocumentValidator. The created instance is
	 * initialised with default {@code XAdESPaths}, allowing support of XAdES v1.1.1, v1.2.2 and v1.3.2.
	 *
	 * @param dssDocument
	 *                    The instance of {@code DSSDocument} to validate
	 */
	public XMLDocumentAnalyzer(final DSSDocument dssDocument) {
		this(dssDocument, initXAdESPathsHolders());
	}

	private static List<XAdESPath> initXAdESPathsHolders() {
		List<XAdESPath> xadesPathsHolders = new ArrayList<>();
		xadesPathsHolders.add(new XAdES111Path());
		xadesPathsHolders.add(new XAdES122Path());
		xadesPathsHolders.add(new XAdES132Path());
		return xadesPathsHolders;
	}

	/**
	 * Constructor for XMLDocumentValidator allowing to provide a custom list of XAdES Path holders.
	 * Can be used to enforce signature validation of a certain XAdES version(s) only.
	 *
	 * @param dssDocument
	 *                    The instance of {@code DSSDocument} to validate
	 */
	public XMLDocumentAnalyzer(final DSSDocument dssDocument, final List<XAdESPath> xadesPathHolders) {
		Objects.requireNonNull(dssDocument, "Document to be validated cannot be null!");
		Objects.requireNonNull(xadesPathHolders, "XAdES Path holders cannot be null!");
		this.document = dssDocument;
		this.domDocument = toDomDocument(dssDocument, xadesPathHolders);
	}

	private XAdESDOMDocument toDomDocument(DSSDocument document, List<XAdESPath> xadesPathsHolders) {
		try {
			return new XAdESDOMDocument(DomUtils.buildDOM(document), xadesPathsHolders);
		} catch (Exception e) {
			throw new IllegalInputException(String.format("An XML file is expected : %s", e.getMessage()), e);
		}
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		return DomUtils.startsWithXmlPreamble(dssDocument) && !EvidenceRecordAnalyzerFactory.isSupportedDocument(dssDocument);
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
		final NodeList signatureNodeList = domDocument.getSignatureNodes();
		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			final Element signatureEl = (Element) signatureNodeList.item(ii);
			final Node parent = signatureEl.getParentNode();
			final String nodeName = parent.getNodeName();
			final String ns = parent.getNamespaceURI();
			
			if ("saml2:Assertion".equals(nodeName) && DSSXMLUtils.SAML_NAMESPACE.isSameUri(ns)) {
				continue; // skip signed assertions
			}

			XAdESDOMElement signatureDomElement = new XAdESDOMElement(signatureEl, domDocument);
			final XAdESSignature xadesSignature = new XAdESSignature(signatureDomElement);
			xadesSignature.setFilename(document.getName());
			xadesSignature.setDetachedContents(detachedContents);
			xadesSignature.setContainerContents(containerContents);
			xadesSignature.setSigningCertificateSource(signingCertificateSource);
			xadesSignature.setDisableXSWProtection(disableXSWProtection);
			xadesSignature.initBaselineRequirementsChecker(certificateVerifier);
			validateSignaturePolicy(xadesSignature);
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
	 * @deprecated since DSS 6.5. To be removed.
	 */
	@Deprecated
	public List<XAdESPath> getXAdESPathsHolder() {
		return domDocument.getXAdESPathHolders();
	}

	/**
	 * This adds a {@code XAdESPaths}. This is useful when the signature follows a
	 * particular schema.
	 *
	 * @param xadesPathsHolder {@link XAdESPath}
	 * @deprecated since DSS 6.5. Please provide a final version of XAdES Paths using constructor
	 *             {@code new XMLDocumentValidator(DSSDocument dssDocument, List<XAdESPath> xadesPathHolders)}
	 */
	@Deprecated
	public void addXAdESPathsHolder(final XAdESPath xadesPathsHolder) {
		domDocument.getXAdESPathHolders().add(xadesPathsHolder);
	}

	/**
	 * Removes all elements from the list of query holders. The list will be empty after this call returns.
	 *
	 * @deprecated since DSS 6.5. Please provide a final version of XAdES Paths using constructor
	 *             {@code new XMLDocumentValidator(DSSDocument dssDocument, List<XAdESPath> xadesPathHolders)}
	 */
	@Deprecated
	public void clearQueryHolders() {
		domDocument.getXAdESPathHolders().clear();
	}

	/**
	 * Returns the root element of the validating document
	 *
	 * @return {@link Document}
	 */
	public Document getRootElement() {
		return domDocument.getDocument();
	}

	@Override
	protected SignaturePolicyValidator getDefaultSignaturePolicyValidator() {
		return new XMLSignaturePolicyValidator();
	}

}
