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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.enumerations.SigningOperation;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xades.definition.XAdESElement;
import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import eu.europa.esig.dss.xades.definition.xades111.XAdES111Element;
import eu.europa.esig.dss.xades.definition.xades111.XAdES111Path;
import eu.europa.esig.dss.xades.definition.xades122.XAdES122Element;
import eu.europa.esig.dss.xades.definition.xades122.XAdES122Path;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds a XAdES signature
 */
public abstract class XAdESBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESBuilder.class);

	/** The attribute used for timestamp includes */
	public static final String REFERENCED_DATA = "referencedData";

	/** The qualifying properties target */
	public static final String TARGET = "Target";

	/** The URI attribute */
	public static final String URI = "URI";

	/** Xml Id prefix */
	protected static final String ID_PREFIX = "id-";

	/** Id-prefix for TimeStamp element */
	protected static final String TIMESTAMP_PREFIX = "ts-";

	/** Id-prefix for EncapsulatedTimeStamp element */
	protected static final String ENCAPSULATED_TIMESTAMP_PREFIX = "ets-";

	/** Id-prefix for TimeStampValidationData element */
	protected static final String TST_VD_PREFIX = "tsvd-";

	/** Id-prefix for AnyValidationData element */
	protected static final String ANY_VD_PREFIX = "avd-";

	/**
	 * This variable holds the {@code XAdESPaths} which contains all constants and
	 * queries needed to cope with the default signature schema.
	 */
	protected XAdESPath xadesPath;

	/**
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
	 * Empty constructor
	 */
	protected XAdESBuilder() {
		// empty
	}

	/**
	 * The default constructor.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier}
	 */
	protected XAdESBuilder(final CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	/**
	 * This method creates the xades:CertDigest DOM object.
	 * 
	 * <pre>
	 * {@code
	 * 		<CertDigest>
	 * 	       <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	 * 	       <ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
	 * 	    </CertDigest>
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
	protected void incorporateCertDigest(final Element parentDom, final DigestAlgorithm digestAlgorithm,
										 final Token token) {
		final Element certDigestDom = DomUtils.addElement(documentDom, parentDom, getXadesNamespace(),
				getCurrentXAdESElements().getElementCertDigest());
		incorporateDigestMethod(certDigestDom, digestAlgorithm);
		incorporateDigestValue(certDigestDom, digestAlgorithm, token);
	}

	/**
	 * This method creates the ds:DigestMethod DOM object.
	 *
	 * <pre>
	 * {@code
	 * 	   <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	 * }
	 * </pre>
	 *
	 * @param parentDom
	 *            the parent element
	 * @param digestAlgorithm
	 *            the digest algorithm to use
	 */
	protected void incorporateDigestMethod(final Element parentDom, final DigestAlgorithm digestAlgorithm) {
		DSSNamespace namespace = getDigestAlgAndValueNamespace();
		DSSXMLUtils.incorporateDigestMethod(parentDom, digestAlgorithm, namespace);
	}

	/**
	 * This method creates the ds:DigestValue DOM object for a given {@code Token}
	 *
	 * <pre>
	 * {@code
	 * 	   <ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
	 * }
	 * </pre>
	 *
	 * @param parentDom
	 *            the parent element
	 * @param digestAlgorithm
	 *            the digest algorithm to use
	 * @param token
	 *            {@link Token} to compute Digest from
	 */
	protected void incorporateDigestValue(final Element parentDom, final DigestAlgorithm digestAlgorithm, Token token) {
		final String base64EncodedDigestBytes = Utils.toBase64(token.getDigest(digestAlgorithm));
		if (LOG.isTraceEnabled()) {
			LOG.trace("Digest value for the token with Id [{}] --> {}", token.getDSSIdAsString(), base64EncodedDigestBytes);
		}
		incorporateDigestValue(parentDom, base64EncodedDigestBytes);
	}

	/**
	 * This method creates the ds:DigestValue DOM object.
	 *
	 * <pre>
	 * {@code
	 * 	   <ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
	 * }
	 * </pre>
	 *
	 * @param parentDom {@link Element} the parent element
	 * @param base64EncodedDigestBytes {@link String} base64 encoded digest value
	 */
	protected void incorporateDigestValue(final Element parentDom, String base64EncodedDigestBytes) {
		DSSNamespace namespace = getDigestAlgAndValueNamespace();
		DSSXMLUtils.incorporateDigestValue(parentDom, base64EncodedDigestBytes, namespace);
	}

	private DSSNamespace getDigestAlgAndValueNamespace() {
		return XAdESNamespace.XADES_111.isSameUri(getXadesNamespace().getUri()) ?
				getXadesNamespace() : getXmldsigNamespace();
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
	 * @param digestAlgorithm
	 *            {@link DigestAlgorithm} to use
	 * @return {@link Element}
	 */
	protected Element incorporateCert(final Element parentDom, final CertificateToken certificate,
									  DigestAlgorithm digestAlgorithm) {

		final Element certDom = DomUtils.addElement(documentDom, parentDom, getXadesNamespace(), getCurrentXAdESElements().getElementCert());

		incorporateCertDigest(certDom, digestAlgorithm, certificate);

		if (params.isEn319132()) {
			incorporateIssuerV2(certDom, certificate);
		} else {
			incorporateIssuerV1(certDom, certificate);
		}

		return certDom;
	}

	/**
	 * Incorporates IssuerSerial element
	 *
	 * @param parentDom {@link Element}
	 * @param certificate {@link CertificateToken} to get issuer for
	 */
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

	/**
	 * Incorporates IssuerSerialV2 element
	 *
	 * @param parentDom {@link Element}
	 * @param certificate {@link CertificateToken} to get issuer for
	 */
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
		List<String> ids = new ArrayList<>();
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
	 *
	 * @return {@link DSSDocument}
	 */
	protected DSSDocument createXmlDocument() {
		byte[] bytes;
		if (SigningOperation.SIGN.equals(params.getContext().getOperationKind()) && params.isPrettyPrint()) {
			alignNodes();
			bytes = DomUtils.serializeNode(DSSXMLUtils.getDocWithIndentedSignature(documentDom, params.getDeterministicId(), getNotIndentedObjectIds()));
		} else {
			bytes = DomUtils.serializeNode(documentDom);
		}
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(bytes);
		inMemoryDocument.setMimeType(MimeTypeEnum.XML);
		return inMemoryDocument;
	}

	/**
	 * This method is used to align children indents
	 */
	protected abstract void alignNodes();
	
	/**
	 * This method returns the current used XMLDSig namespace
	 *
	 * @return {@link DSSNamespace}
	 */
	protected DSSNamespace getXmldsigNamespace() {
		return params.getXmldsigNamespace();
	}

	/**
	 * This method returns the current used XAdES namespace
	 *
	 * @return {@link DSSNamespace}
	 */
	protected DSSNamespace getXadesNamespace() {
		return params.getXadesNamespace();
	}

	/**
	 * This method returns the current used XAdES 1.4.1 namespace
	 *
	 * @return {@link DSSNamespace}
	 */
	protected DSSNamespace getXades141Namespace() {
		return params.getXades141Namespace();
	}

	/**
	 * Gets a relevant class containing the list of elements
	 *
	 * @return {@link XAdESElement} implementation
	 */
	protected XAdESElement getCurrentXAdESElements() {
		String xadesURI = getXadesNamespace().getUri();
		if (XAdESNamespace.XADES_132.getUri().equals(xadesURI)) {
			return XAdES132Element.values()[0];
		} else if (XAdESNamespace.XADES_122.getUri().equals(xadesURI)) {
			return XAdES122Element.values()[0];
		} else if (XAdESNamespace.XADES_111.getUri().equals(xadesURI)) {
			return XAdES111Element.values()[0];
		}
		throw new IllegalArgumentException("Unsupported URI : " + xadesURI);
	}

	/**
	 * Gets a relevant class containing the list of paths
	 *
	 * @return {@link XAdESPath} implementation
	 */
	protected XAdESPath getCurrentXAdESPath() {
		String xadesURI = getXadesNamespace().getUri();
		if (Utils.areStringsEqual(XAdESNamespace.XADES_132.getUri(), xadesURI)) {
			return new XAdES132Path();
		} else if (Utils.areStringsEqual(XAdESNamespace.XADES_122.getUri(), xadesURI)) {
			return new XAdES122Path();
		} else if (Utils.areStringsEqual(XAdESNamespace.XADES_111.getUri(), xadesURI)) {
			return new XAdES111Path();
		} else {
			throw new IllegalArgumentException("Unsupported URI : " + xadesURI);
		}
	}

	/**
	 * Creates SpDocSpecification DOM object:
	 *
	 * <pre>
	 * {@code
	 * 	<xades141:SPDocSpecification xmlns:xades141="http://uri.etsi.org/01903/v1.4.1#">
	 * 	    <xades:Identifier>1.2.3.4.5</xades:Identifier>
	 * 	</xades141:SPDocSpecification>
	 * }
	 * </pre>
	 *
	 * @param parentElement {@link Element} element to create the new object inside
	 * @param spDocSpecification {@link SpDocSpecification}
	 */
	protected void incorporateSPDocSpecification(Element parentElement, SpDocSpecification spDocSpecification) {
		final Element spDocSpecElement = DomUtils.addElement(documentDom, parentElement,
				getXades141Namespace(), XAdES141Element.SP_DOC_SPECIFICATION);
		DomUtils.addNamespaceAttribute(spDocSpecElement, getXades141Namespace());

		final Element identifierElement = DomUtils.addElement(documentDom, spDocSpecElement,
				getXadesNamespace(), getCurrentXAdESElements().getElementIdentifier());
		if (spDocSpecification.getQualifier() != null) {
			identifierElement.setAttribute(XAdES132Attribute.QUALIFIER.getAttributeName(),
					spDocSpecification.getQualifier().getValue());
		}
		DomUtils.setTextNode(documentDom, identifierElement, spDocSpecification.getId());

		if (Utils.isStringNotEmpty(spDocSpecification.getDescription())) {
			final Element descriptionElement = DomUtils.addElement(documentDom, spDocSpecElement, getXadesNamespace(),
					getCurrentXAdESElements().getElementDescription());
			DomUtils.setTextNode(documentDom, descriptionElement, spDocSpecification.getDescription());
		}

		if (Utils.isArrayNotEmpty(spDocSpecification.getDocumentationReferences())) {
			final Element documentReferencesElement = DomUtils.addElement(documentDom, spDocSpecElement, getXadesNamespace(),
					getCurrentXAdESElements().getElementDocumentationReferences());

			for (String docRef : spDocSpecification.getDocumentationReferences()) {
				final Element documentReferenceElement = DomUtils.addElement(documentDom, documentReferencesElement, getXadesNamespace(),
						getCurrentXAdESElements().getElementDocumentationReference());
				DomUtils.setTextNode(documentDom, documentReferenceElement, docRef);
			}
		}
	}

	/**
	 * Transforms a DSS Identifier to an XML Id type
	 *
	 * @param identifier {@link Identifier} to transform
	 * @return {@link String}
	 */
	protected String toXmlIdentifier(Identifier identifier) {
		return ID_PREFIX + DSSUtils.getSHA1Digest(identifier.asXmlId());
	}
	
}
