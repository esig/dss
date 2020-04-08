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
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureUtils;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;
import eu.europa.esig.dss.xades.definition.XAdESPaths;
import eu.europa.esig.dss.xades.definition.xades111.XAdES111Paths;
import eu.europa.esig.dss.xades.definition.xades122.XAdES122Paths;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Paths;
import eu.europa.esig.dss.xades.validation.scope.XAdESSignatureScopeFinder;

/**
 * Validator of XML Signed document
 *
 */
public class XMLDocumentValidator extends SignedDocumentValidator {

	private static final byte[] xmlPreamble = new byte[] { '<' };
	private static final byte[] xmlWithBomPreample = new byte[] { -17, -69, -65, '<' }; // UTF-8 with BOM

	/**
	 * This variable contains the list of {@code XAdESPaths} adapted to the specific
	 * signature schema.
	 */
	protected List<XAdESPaths> xadesPathsHolders;

	protected Document rootElement;

	private boolean disableXSWProtection = false;

	private List<AdvancedSignature> signatures;

	static {
		XAdESNamespaces.registerNamespaces();
	}

	XMLDocumentValidator() {
	}

	/**
	 * The default constructor for XMLDocumentValidator. The created instance is
	 * initialised with default {@code XAdESPaths} .
	 *
	 * @param dssDocument
	 *                    The instance of {@code DSSDocument} to validate
	 */
	public XMLDocumentValidator(final DSSDocument dssDocument) {

		super(new XAdESSignatureScopeFinder());
		this.document = dssDocument;
		this.rootElement = DomUtils.buildDOM(dssDocument);

		xadesPathsHolders = new ArrayList<>();
		xadesPathsHolders.add(new XAdES111Paths());
		xadesPathsHolders.add(new XAdES122Paths());
		xadesPathsHolders.add(new XAdES132Paths());
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		return DSSUtils.compareFirstBytes(dssDocument, xmlPreamble) || DSSUtils.compareFirstBytes(dssDocument, xmlWithBomPreample);
	}

	/**
	 * NOT RECOMMENDED : This parameter allows to disable protection against XML
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
	public List<AdvancedSignature> getSignatures() {
		if (signatures != null) {
			return signatures;
		}

		signatures = new ArrayList<>();
		final NodeList signatureNodeList = DomUtils.getNodeList(rootElement, XAdES132Paths.ALL_SIGNATURE_WITH_NO_COUNTERSIGNATURE_AS_PARENT_PATH);
		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {

			final Element signatureEl = (Element) signatureNodeList.item(ii);
			final XAdESSignature xadesSignature = new XAdESSignature(signatureEl, xadesPathsHolders);
			xadesSignature.setSignatureFilename(document.getName());
			xadesSignature.setDetachedContents(detachedContents);
			xadesSignature.setContainerContents(containerContents);
			xadesSignature.setProvidedSigningCertificateToken(providedSigningCertificateToken);
			xadesSignature.setDisableXSWProtection(disableXSWProtection);
			xadesSignature.prepareOfflineCertificateVerifier(certificateVerifier);
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
		Objects.requireNonNull(signatureId, "Signature Id cannot be null");
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
	public List<DSSDocument> getOriginalDocuments(final String signatureId) {
		Objects.requireNonNull(signatureId, "Signature Id cannot be null");

		List<AdvancedSignature> signatureList = getSignatures();
		for (AdvancedSignature advancedSignature : signatureList) {
			if (signatureId.equals(advancedSignature.getId())) {
				return getOriginalDocuments(advancedSignature);
			}
		}
		return Collections.emptyList();
	}
	
	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		XAdESSignature signature = (XAdESSignature) advancedSignature;
		return XAdESSignatureUtils.getSignerDocuments(signature);
	}

	/**
	 * This getter returns the {@code XAdESPaths}
	 *
	 * @return
	 */
	public List<XAdESPaths> getXAdESPathsHolder() {
		return xadesPathsHolders;
	}

	/**
	 * This adds a {@code XAdESPaths}. This is useful when the signature follows a
	 * particular schema.
	 *
	 * @param xadesPathsHolder
	 */
	public void addXAdESPathsHolder(final XAdESPaths xadesPathsHolder) {
		xadesPathsHolders.add(xadesPathsHolder);
	}

	/**
	 * Removes all of the elements from the list of query holders. The list will be empty after this call returns.
	 */
	public void clearQueryHolders() {
		xadesPathsHolders.clear();
	}

	/**
	 * @return
	 */
	public Document getRootElement() {
		return rootElement;
	}

}
