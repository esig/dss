package eu.europa.esig.dss.xades.signature;

import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;

/**
 * This class builds a ds:Manifest element
 * 
 * <pre>
 * {@code
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
 * }
 * </pre>
 * 
 */
public class ManifestBuilder {

	private final String manifestId;
	private final DigestAlgorithm digestAlgorithm;
	private final List<DSSDocument> documents;

	/**
	 * Constructor for the builder (the Id of the Manifest tag will be equals to "manifest")
	 * 
	 * @param digestAlgorithm
	 *            the digest algorithm to be used
	 * @param documents
	 *            the documents to include
	 */
	public ManifestBuilder(DigestAlgorithm digestAlgorithm, List<DSSDocument> documents) {
		this("manifest", digestAlgorithm, documents);
	}

	/**
	 * Constructor for the builder
	 * 
	 * @param manifestId
	 *            the Id of the Manifest tag
	 * @param digestAlgorithm
	 *            the digest algorithm to be used
	 * @param documents
	 *            the documents to include
	 */
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
			Text textNode = documentDom.createTextNode(document.getDigest(digestAlgorithm));
			digestValueDom.appendChild(textNode);

		}

		return DomUtils.createDssDocumentFromDomDocument(documentDom, manifestId);
	}

}
