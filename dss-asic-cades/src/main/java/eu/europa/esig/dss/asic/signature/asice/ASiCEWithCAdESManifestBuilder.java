package eu.europa.esig.dss.asic.signature.asice;

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

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
 *					<DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#" Algorithm=
"http://www.w3.org/2001/04/xmlenc#sha256"/>
 *					<DigestValue xmlns=
"http://www.w3.org/2000/09/xmldsig#">OuL0HMJE899y+uJtyNnTt5B/gFrrw8adNczI+9w9GDQ=</DigestValue>
 *				</asic:DataObjectReference>
 *			</asic:SigReference>
 *		</asic:ASiCManifest>
 * </code>
 * </pre>
 */
public class ASiCEWithCAdESManifestBuilder extends AbstractManifestBuilder {

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

		addSigReference(documentDom, asicManifestDom, signatureUri, MimeType.PKCS7);

		for (DSSDocument document : documents) {
			addDataObjectReference(documentDom, asicManifestDom, document, digestAlgorithm);
		}

		return documentDom;
	}
}
