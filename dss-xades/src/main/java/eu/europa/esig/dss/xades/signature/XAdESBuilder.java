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
package eu.europa.esig.dss.xades.signature;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x509.IssuerSerial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSNamespace;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.ProfileParameters.Operation;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.XAdESElement;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;
import eu.europa.esig.dss.xades.definition.XAdESPaths;
import eu.europa.esig.dss.xades.definition.xades111.XAdES111Element;
import eu.europa.esig.dss.xades.definition.xades111.XAdES111Paths;
import eu.europa.esig.dss.xades.definition.xades122.XAdES122Element;
import eu.europa.esig.dss.xades.definition.xades122.XAdES122Paths;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Paths;
import eu.europa.esig.dss.xades.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.xades.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;

public abstract class XAdESBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESBuilder.class);

	public static final String REFERENCED_DATA = "referencedData";
	public static final String SIGNATURE = "Signature";
	public static final String TARGET = "Target";
	public static final String URI = "URI";

	/**
	 * This variable holds the {@code XAdESPaths} which contains all constants and
	 * queries needed to cope with the default signature schema.
	 */
	protected XAdESPaths xadesPaths;

	/*
	 * This variable is a reference to the set of parameters relating to the structure and process of the creation or
	 * extension of the electronic signature.
	 */
	protected XAdESSignatureParameters params;

	/**
	 * This is the variable which represents the root XML document root (with signature).
	 */
	protected Document documentDom;

	/**
	 * Reference to the object in charge of certificates validation
	 */
	protected CertificateVerifier certificateVerifier;

	/**
	 * The default constructor.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier}
	 */
	public XAdESBuilder(final CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}
	
	/**
	 * This method creates the ds:DigestMethod DOM object
	 * 
	 * <pre>
	 * {@code
	 * 		<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
	 * }
	 * </pre>
	 *
	 * @param parentDom
	 *            the parent element
	 * @param digestAlgorithm
	 *            the digest algorithm xml identifier
	 */
	protected void incorporateDigestMethod(final Element parentDom, final DigestAlgorithm digestAlgorithm) {
		final Element digestMethodDom = DomUtils.addElement(documentDom, parentDom, getXmldsigNamespace(), XMLDSigElement.DIGEST_METHOD);
		digestMethodDom.setAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName() , digestAlgorithm.getUri());
	}

	/**
	 * This method creates the ds:DigestValue DOM object.
	 * 
	 * <pre>
	 * {@code
	 * 		<ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
	 * }
	 * </pre>
	 *
	 * @param parentDom
	 *            the parent element
	 * @param dssReference
	 *            the current reference to incorporate
	 * @param digestAlgorithm
	 *            the digest algorithm to be used
	 * @param originalDocument
	 *            the document to be digested
	 */
	protected void incorporateDigestValue(final Element parentDom, DSSReference dssReference, final DigestAlgorithm digestAlgorithm,
			final DSSDocument originalDocument) {

		final Element digestValueDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.DIGEST_VALUE);

		String base64EncodedDigestBytes = null;
		if (params.isManifestSignature()) {
			DSSTransform dssTransform = getUniqueCanonicalizationTransform(dssReference);
			Document doc = DomUtils.buildDOM(originalDocument);
			
			byte[] bytes = dssTransform.getBytesAfterTranformation(doc);
			base64EncodedDigestBytes = Utils.toBase64(DSSUtils.digest(digestAlgorithm, bytes));
		} else if (params.isEmbedXML()) {
			DSSTransform dssTransform = getUniqueCanonicalizationTransform(dssReference);

			Document doc = DomUtils.buildDOM(originalDocument);
			Element root = doc.getDocumentElement();

			Document doc2 = DomUtils.buildDOM();
			final Element dom = DomUtils.createElementNS(doc2, getXmldsigNamespace(), XMLDSigElement.OBJECT);
			final Element dom2 = DomUtils.createElementNS(doc2, getXmldsigNamespace(), XMLDSigElement.OBJECT);
			doc2.appendChild(dom2);
			dom2.appendChild(dom);
			dom.setAttribute(XMLDSigAttribute.ID.getAttributeName(), dssReference.getUri().substring(1));

			Node adopted = doc2.adoptNode(root);
			dom.appendChild(adopted);

			byte[] bytes = dssTransform.getBytesAfterTranformation(dom);
			base64EncodedDigestBytes = Utils.toBase64(DSSUtils.digest(digestAlgorithm, bytes));
		} else {
			base64EncodedDigestBytes = originalDocument.getDigest(digestAlgorithm);
		}

		LOG.trace("C14n Digest value {} --> {}", parentDom.getNodeName(), base64EncodedDigestBytes);
		final Text textNode = documentDom.createTextNode(base64EncodedDigestBytes);
		digestValueDom.appendChild(textNode);
		parentDom.appendChild(digestValueDom);
	}

	private DSSTransform getUniqueCanonicalizationTransform(DSSReference dssReference) {
		List<DSSTransform> transforms = dssReference.getTransforms();
		if (Utils.collectionSize(transforms) != 1) {
			throw new DSSException("Only one transformation is supported");
		}
		DSSTransform dssTransform = transforms.get(0);
		if (!(dssTransform instanceof CanonicalizationTransform)) {
			throw new DSSException("Only canonicalization transform is allowed in the given use case");
		}
		return dssTransform;
	}

	/**
	 * This method creates the ds:DigestValue DOM object.
	 * 
	 * <pre>
	 * {@code
	 * 		<ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
	 * }
	 * </pre>
	 *
	 * @param parentDom
	 *            the parent element
	 * @param digestAlgorithm
	 *            the digest algorithm to use
	 * @param token
	 *            the token to be digested
	 */
	protected void incorporateDigestValue(final Element parentDom, final DigestAlgorithm digestAlgorithm, final Token token) {
		Element digestValueDom = null;
		if (XAdESNamespaces.XADES_111.isSameUri(getXadesNamespace().getUri())) {
			digestValueDom = DomUtils.createElementNS(documentDom, getXadesNamespace(), XAdES111Element.DIGEST_VALUE);
		} else {
			digestValueDom = DomUtils.createElementNS(documentDom, getXmldsigNamespace(), XMLDSigElement.DIGEST_VALUE);
		}
		final String base64EncodedDigestBytes = Utils.toBase64(token.getDigest(digestAlgorithm));
		if (LOG.isTraceEnabled()) {
			LOG.trace("Digest value {} --> {}", parentDom.getNodeName(), base64EncodedDigestBytes);
		}
		final Text textNode = documentDom.createTextNode(base64EncodedDigestBytes);
		digestValueDom.appendChild(textNode);

		parentDom.appendChild(digestValueDom);
	}

	/**
	 * Incorporates the certificate's references as a child of the given parent node. The first element of the
	 * {@code X509Certificate} {@code List} MUST be the
	 * signing certificate.
	 *
	 * @param signingCertificateDom
	 *            DOM parent element
	 * @param certificates
	 *            {@code List} of the certificates to be incorporated
	 */
	protected void incorporateCertificateRef(final Element signingCertificateDom, final Set<CertificateToken> certificates) {
		for (final CertificateToken certificate : certificates) {
			final Element certDom = incorporateCert(signingCertificateDom, certificate);
			incorporateIssuerV1(certDom, certificate);
		}
	}

	/**
	 * Creates Cert DOM object:
	 * 
	 * <pre>
	 * {@code
	 * 		<Cert>
	 * 			<CertDigest>
	 * 				<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	 * 				<ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
	 * 			</CertDigest>
	 * 			<IssuerSerial>
	 * 				<ds:X509IssuerName>CN=ICA A,O=DSS,C=AA</ds:X509IssuerName>
	 * 				<ds:X509SerialNumber>4</ds:X509SerialNumber>
	 *			</IssuerSerial>
	 *		</Cert>
	 * }
	 * </pre>
	 * 
	 * @param parentDom
	 *            the parent element
	 * @param certificate
	 *            the certificate to be added
	 */
	protected Element incorporateCert(final Element parentDom, final CertificateToken certificate) {
		final Element certDom = DomUtils.addElement(documentDom, parentDom, getXadesNamespace(), getCurrentXAdESElements().getElementCert());

		final Element certDigestDom = DomUtils.addElement(documentDom, certDom, getXadesNamespace(), getCurrentXAdESElements().getElementCertDigest());

		final DigestAlgorithm signingCertificateDigestMethod = params.getSigningCertificateDigestMethod();
	
		Element digestMethodDom = null;
		if (XAdESNamespaces.XADES_111.isSameUri(getXadesNamespace().getUri())) {
			digestMethodDom = DomUtils.addElement(documentDom, certDigestDom, getXadesNamespace(), XAdES111Element.DIGEST_METHOD);
		} else {
			digestMethodDom = DomUtils.addElement(documentDom, certDigestDom, getXmldsigNamespace(), XMLDSigElement.DIGEST_METHOD);
		}
		digestMethodDom.setAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName(), signingCertificateDigestMethod.getUri());
		
		incorporateDigestValue(certDigestDom, signingCertificateDigestMethod, certificate);
		return certDom;
	}

	protected void incorporateIssuerV1(final Element parentDom, final CertificateToken certificate) {
		final Element issuerSerialDom = DomUtils.addElement(documentDom, parentDom, getXadesNamespace(), getCurrentXAdESElements().getElementIssuerSerial());

		final Element x509IssuerNameDom = DomUtils.addElement(documentDom, issuerSerialDom, getXmldsigNamespace(), XMLDSigElement.X509_ISSUER_NAME);
				
		final String issuerX500PrincipalName = certificate.getIssuerX500Principal().getName();
		DomUtils.setTextNode(documentDom, x509IssuerNameDom, issuerX500PrincipalName);

		final Element x509SerialNumberDom = DomUtils.addElement(documentDom, issuerSerialDom, getXmldsigNamespace(), XMLDSigElement.X509_SERIAL_NUMBER);
		
		final BigInteger serialNumber = certificate.getSerialNumber();
		final String serialNumberString = serialNumber.toString();
		DomUtils.setTextNode(documentDom, x509SerialNumberDom, serialNumberString);
	}

	protected void incorporateIssuerV2(final Element parentDom, final CertificateToken certificate) {
		final Element issuerSerialDom = DomUtils.addElement(documentDom, parentDom, getXadesNamespace(), getCurrentXAdESElements().getElementIssuerSerialV2());

		IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(certificate);
		String issuerBase64 = Utils.toBase64(DSSASN1Utils.getDEREncoded(issuerSerial));
		DomUtils.setTextNode(documentDom, issuerSerialDom, issuerBase64);
	}
	
	/**
	 * Returns list of object ids that must not be indented in any case
	 * @return list of object ids to no indent
	 */
	private List<String> getNotIndentedObjectIds() {
		List<String> ids = new ArrayList<String>();
		List<DSSReference> dssReferences = params.getReferences();
		if (dssReferences != null) {
			for (DSSReference reference : dssReferences) {
				// do not change external objects
				if (DSSXMLUtils.isObjectReferenceType(reference.getType())) {
					ids.add(DomUtils.getId(reference.getUri()));
				}
			}
		}
		return ids;
	}
	
	/**
	 * Creates {@link DSSDocument} from the current documentDom
	 * @return {@link DSSDocument}
	 */
	protected DSSDocument createXmlDocument() {
		byte[] bytes;
		if (Operation.SIGNING.equals(params.getContext().getOperationKind()) && params.isPrettyPrint()) {
			alignNodes();
			bytes = DSSXMLUtils.serializeNode(DSSXMLUtils.getDocWithIndentedSignatures(documentDom, params.getDeterministicId(), getNotIndentedObjectIds()));
		} else {
			bytes = DSSXMLUtils.serializeNode(documentDom);
		}
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(bytes);
		inMemoryDocument.setMimeType(MimeType.XML);
		return inMemoryDocument;
	}
	
	protected abstract void alignNodes();
	

	/**
	 * This method returns the current used XMLDSig namespace. Try to determine from the signature, from the parameters or the default value
	 */
	protected DSSNamespace getXmldsigNamespace() {
		DSSNamespace xmldsigNamespace = params.getXmldsigNamespace();
		if (xmldsigNamespace == null) {
			LOG.warn("Current XMLDSig namespace not found in the parameters (use the default XMLDSig)");
			xmldsigNamespace = XAdESNamespaces.XMLDSIG;

		}
		return xmldsigNamespace;
	}

	/**
	 * This method returns the current used XAdES namespace. Try to determine from the signature, from the parameters or the default value
	 */
	protected DSSNamespace getXadesNamespace() {
		DSSNamespace xadesNamespace = params.getXadesNamespace();
		if (xadesNamespace == null) {
			LOG.warn("Current XAdES namespace not found in the parameters (use the default XAdES 1.3.2)");
			xadesNamespace = XAdESNamespaces.XADES_132;

		}
		return xadesNamespace;
	}

	/**
	 * This method returns the current used XAdES 1.4.1 namespace. Try to determine from the signature, from the parameters or the default value
	 */
	protected DSSNamespace getXades141Namespace() {
		DSSNamespace xades141Namespace = params.getXades141Namespace();
		if (xades141Namespace == null) {
			LOG.warn("Current XAdES 1.4.1 namespace not found in the parameters (use the default XAdES 1.4.1)");
			xades141Namespace = XAdESNamespaces.XADES_141;

		}
		return xades141Namespace;
	}
	
	protected XAdESElement getCurrentXAdESElements() {
		String xadesURI = getXadesNamespace().getUri();
		if (XAdESNamespaces.XADES_132.getUri().equals(xadesURI)) {
			return XAdES132Element.values()[0];
		} else if (XAdESNamespaces.XADES_122.getUri().equals(xadesURI)) {
			return XAdES122Element.values()[0];
		} else if (XAdESNamespaces.XADES_111.getUri().equals(xadesURI)) {
			return XAdES111Element.values()[0];
		}
		throw new DSSException("Unsupported URI : " + xadesURI);
	}

	protected XAdESPaths getCurrentXAdESPaths() {
		String xadesURI = getXadesNamespace().getUri();
		if (Utils.areStringsEqual(XAdESNamespaces.XADES_132.getUri(), xadesURI)) {
			return new XAdES132Paths();
		} else if (Utils.areStringsEqual(XAdESNamespaces.XADES_122.getUri(), xadesURI)) {
			return new XAdES122Paths();
		} else if (Utils.areStringsEqual(XAdESNamespaces.XADES_111.getUri(), xadesURI)) {
			return new XAdES111Paths();
		} else {
			throw new DSSException("Unsupported URI : " + xadesURI);
		}
	}
	
}
