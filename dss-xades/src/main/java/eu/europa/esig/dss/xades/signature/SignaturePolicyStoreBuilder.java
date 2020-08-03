package eu.europa.esig.dss.xades.signature;

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.xades111.XAdES111Paths;
import eu.europa.esig.dss.xades.definition.xades122.XAdES122Paths;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Paths;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class SignaturePolicyStoreBuilder extends ExtensionBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(SignaturePolicyStoreBuilder.class);

	protected SignaturePolicyStoreBuilder(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore) {

		params = new XAdESSignatureParameters();

		documentDom = DomUtils.buildDOM(document);

		final NodeList signatureNodeList = documentDom.getElementsByTagNameNS(XMLNS, XMLDSigElement.SIGNATURE.getTagName());
		if (signatureNodeList.getLength() == 0) {
			throw new DSSException("No signature to extend!");
		}

		for (int ii = 0; ii < signatureNodeList.getLength(); ii++) {
			currentSignatureDom = (Element) signatureNodeList.item(ii);

			xadesSignature = new XAdESSignature(currentSignatureDom, Arrays.asList(new XAdES111Paths(), new XAdES122Paths(), new XAdES132Paths()));

			xadesPaths = xadesSignature.getXAdESPaths();

			final String currentSignatureId = currentSignatureDom.getAttribute(XMLDSigAttribute.ID.getAttributeName());
//			if ((signatureId != null) && !signatureId.equals(currentSignatureId)) {
//				continue;
//			}

			ensureUnsignedProperties();
			ensureUnsignedSignatureProperties();
			assertSignatureValid(xadesSignature);

			Element signaturePolicyIdentifierElement = DomUtils.getElement(currentSignatureDom, xadesPaths.getSignaturePolicyIdentifier());
			if (signaturePolicyIdentifierElement != null) {
				final Digest digest = DSSXMLUtils
						.getDigestAndValue(DomUtils.getElement(signaturePolicyIdentifierElement, xadesPaths.getCurrentSignaturePolicyDigestAlgAndValue()));
				if (digest != null) {
					byte[] computedDigest = Utils.fromBase64(signaturePolicyStore.getSignaturePolicyContent().getDigest(digest.getAlgorithm()));
					if (Arrays.equals(digest.getValue(), computedDigest)) {

						String spDocSpecification = signaturePolicyStore.getSpDocSpecification();
						if (!DSSUtils.isUrnOid(spDocSpecification)) {
							throw new DSSException("SPDocSpecification must contains an OIDAsURN");
						}

						Element signaturePolicyStoreElement = DomUtils.addElement(documentDom, unsignedSignaturePropertiesDom, getXades141Namespace(),
								XAdES141Element.SIGNATURE_POLICY_STORE);

						Element spDocSpecElement = DomUtils.addElement(documentDom, signaturePolicyStoreElement, getXades141Namespace(),
								XAdES141Element.SP_DOC_SPECIFICATION);
						Element identifierElement = DomUtils.addElement(documentDom, spDocSpecElement,
								getXadesNamespace(), getCurrentXAdESElements().getElementIdentifier());
						identifierElement.setAttribute(XAdES132Attribute.QUALIFIER.getAttributeName(), ObjectIdentifierQualifier.OID_AS_URN.getValue());
						DomUtils.setTextNode(documentDom, identifierElement, spDocSpecification);

						Element policyDocElement = DomUtils.addElement(documentDom, signaturePolicyStoreElement, getXades141Namespace(),
								XAdES141Element.SIGNATURE_POLICY_DOCUMENT);

						DomUtils.setTextNode(documentDom, policyDocElement,
								Utils.toBase64(DSSUtils.toByteArray(signaturePolicyStore.getSignaturePolicyContent())));

					} else {
						throw new DSSException("Expected digest " + digest);
					}
				} else {
					LOG.warn("No defined digest for signature {}", currentSignatureId);
				}
			} else {
				LOG.warn("No defined SignaturePolicyIdentifier for signature {}", currentSignatureId);
			}
		}

		return createXmlDocument();
	}

}
