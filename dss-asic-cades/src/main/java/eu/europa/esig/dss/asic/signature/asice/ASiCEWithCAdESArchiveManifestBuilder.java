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
 * This class is used to generate the ASiCArchiveManifest.xml content (ASiC-E)
 *
 * Sample:
 * 
 * <pre>
 * <code>
 * 		<asic:ASiCManifest xmlns:asic="http://uri.etsi.org/02918/v1.2.1#">
 *			<asic:SigReference URI="META-INF/archive_timestamp.tst" MimeType="application/vnd.etsi.timestamp-token"/>
 *			<asic:DataObjectReference URI="META-INF/signature.p7s" MimeType="application/x-pkcs7-signature">
 *				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 *				<DigestValue>3Qeos8...</DigestValue>
 *			</asic:DataObjectReference>
 *			<asic:DataObjectReference URI="toBeSigned.txt" MimeType="text/plain">
 *				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/> 
 *				<DigestValue>JJZt...</DigestValue>
 *			</asic:DataObjectReference>
 *			<asic:DataObjectReference URI="META-INF/ASiCManifest_1.xml" MimeType="text/xml">
 *				<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 *				<DigestValue>g5dY...</DigestValue>
 *			</asic:DataObjectReference>
 * 		</asic:ASiCManifest>
 * </code>
 * </pre>
 */
public class ASiCEWithCAdESArchiveManifestBuilder extends AbstractManifestBuilder {

	private final List<DSSDocument> signatures;
	private final List<DSSDocument> documents;
	private final List<DSSDocument> manifests;
	private final DigestAlgorithm digestAlgorithm;
	private final String timestampUri;

	public ASiCEWithCAdESArchiveManifestBuilder(List<DSSDocument> signatures, List<DSSDocument> documents, List<DSSDocument> manifests,
			DigestAlgorithm digestAlgorithm, String timestampUri) {
		this.signatures = signatures;
		this.documents = documents;
		this.manifests = manifests;
		this.digestAlgorithm = digestAlgorithm;
		this.timestampUri = timestampUri;
	}

	public Document build() {
		final Document documentDom = DomUtils.buildDOM();
		final Element asicManifestDom = documentDom.createElementNS(ASiCNamespace.NS, ASiCNamespace.ASIC_MANIFEST);
		documentDom.appendChild(asicManifestDom);

		addSigReference(documentDom, asicManifestDom, timestampUri, MimeType.TST);

		for (DSSDocument signature : signatures) {
			addDataObjectReference(documentDom, asicManifestDom, signature, digestAlgorithm);
		}

		for (DSSDocument document : documents) {
			addDataObjectReference(documentDom, asicManifestDom, document, digestAlgorithm);
		}

		for (DSSDocument manifest : manifests) {
			addDataObjectReference(documentDom, asicManifestDom, manifest, digestAlgorithm);
		}

		return documentDom;
	}

}
