package eu.europa.esig.dss.xades.signature;

import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class builds a ds:Manifest element
 * 
 * <pre>
 * <code>
 * 	<ds:Manifest Id="manifest">
 * 		<ds:Reference URI="l_19420170726bg.pdf">
 * 			<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
 * 			<ds:DigestValue>EUcwRQ....</ds:DigestValue>
 * 		</ds:Reference>
 * 		<ds:Reference URI="l_19420170726cs.pdf">
 * 			<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>
 * 			<ds:DigestValue>NQNnr+F...</ds:DigestValue>
 * 		</ds:Reference>
 * 		...
 * 	</ds:Manifest>
 * </code>
 * </pre>
 * 
 */
public class ManifestBuilder {

	private final String manifestId;
	private final DigestAlgorithm digestAlgorithm;
	private final List<DSSDocument> documents;

	public ManifestBuilder(DigestAlgorithm digestAlgorithm, List<DSSDocument> documents) {
		this("manifest", digestAlgorithm, documents);
	}

	public ManifestBuilder(String manifestId, DigestAlgorithm digestAlgorithm, List<DSSDocument> documents) {
		this.manifestId = manifestId;
		this.digestAlgorithm = digestAlgorithm;
		this.documents = documents;
	}

	public DSSDocument build() {
		Document documentDom = DomUtils.buildDOM();

		Element manifestDom = documentDom.createElementNS(XMLSignature.XMLNS, XAdESBuilder.DS_MANIFEST);
		manifestDom.setAttribute(XAdESBuilder.ID, manifestId);

		documentDom.appendChild(manifestDom);

		for (DSSDocument document : documents) {

			Element referenceDom = DomUtils.addElement(documentDom, manifestDom, XMLSignature.XMLNS, XAdESBuilder.DS_REFERENCE);
			referenceDom.setAttribute(XAdESBuilder.URI, document.getName());

			Element digestMethodDom = DomUtils.addElement(documentDom, referenceDom, XMLSignature.XMLNS, XAdESBuilder.DS_DIGEST_METHOD);
			digestMethodDom.setAttribute(XAdESBuilder.ALGORITHM, digestAlgorithm.getXmlId());

			Element digestValueDom = DomUtils.addElement(documentDom, referenceDom, XMLSignature.XMLNS, XAdESBuilder.DS_DIGEST_VALUE);
			Text textNode = documentDom.createTextNode(Utils.toBase64(DSSUtils.digest(digestAlgorithm, document)));
			digestValueDom.appendChild(textNode);

		}

		return DomUtils.createDssDocumentFromDomDocument(documentDom, null);
	}

}
