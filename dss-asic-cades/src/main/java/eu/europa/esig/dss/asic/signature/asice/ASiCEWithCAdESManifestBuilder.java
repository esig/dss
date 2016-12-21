package eu.europa.esig.dss.asic.signature.asice;

import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.asic.ASiCNamespace;

/**
 * This class is used to generate the ASiCManifest.xml content (ASiC-E)
 *
 * Sample:
 * 
 * <pre>
 * <code>
 * 		<asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#">
 *			<asic:SigReference MimeType="application/pkcs7-signature" URI="META-INF/signature001.p7s">
 *				<asic:DataObjectReference URI="document.txt">
 *					<DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 *					<DigestValue xmlns="http://www.w3.org/2000/09/xmldsig#">OuL0HMJE899y+uJtyNnTt5B/gFrrw8adNczI+9w9GDQ=</DigestValue>
 *				</asic:DataObjectReference>
 *			</asic:SigReference>
 *		</asic:ASiCManifest>
 * </code>
 * </pre>
 */
public class ASiCEWithCAdESManifestBuilder {

	private final List<DSSDocument> documents;
	private final DigestAlgorithm digestAlgorithm;
	private final String signatureUri;

	public ASiCEWithCAdESManifestBuilder(List<DSSDocument> documents, DigestAlgorithm digestAlgorithm, String signatureUri) {
		this.documents = documents;
		this.digestAlgorithm = digestAlgorithm;
		this.signatureUri = signatureUri;
	}

	public Document build() {
		final Document documentDom = DomUtils.buildDOM();
		final Element asicManifestDom = documentDom.createElementNS(ASiCNamespace.NS, ASiCNamespace.ASIC_MANIFEST);
		documentDom.appendChild(asicManifestDom);

		final Element sigReferenceDom = DomUtils.addElement(documentDom, asicManifestDom, ASiCNamespace.NS, ASiCNamespace.SIG_REFERENCE);
		sigReferenceDom.setAttribute("URI", signatureUri);
		sigReferenceDom.setAttribute("MimeType", MimeType.PKCS7.getMimeTypeString());

		for (DSSDocument document : documents) {
			final String detachedDocumentName = document.getName();
			final Element dataObjectReferenceDom = DomUtils.addElement(documentDom, asicManifestDom, ASiCNamespace.NS, ASiCNamespace.DATA_OBJECT_REFERENCE);
			dataObjectReferenceDom.setAttribute("URI", detachedDocumentName);

			final Element digestMethodDom = DomUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestMethod");
			digestMethodDom.setAttribute("Algorithm", digestAlgorithm.getXmlId());

			final Element digestValueDom = DomUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestValue");
			final Text textNode = documentDom.createTextNode(document.getDigest(digestAlgorithm));
			digestValueDom.appendChild(textNode);
		}

		return documentDom;
	}
}
