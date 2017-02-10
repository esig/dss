package eu.europa.esig.dss.asic.signature.asice;

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.asic.ManifestNamespace;

/**
 * This class is used to build the manifest.xml file (ASiC-E).
 * 
 * Sample:
 * 
 * <pre>
 * <code>
 * 		<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
 * 			<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.etsi.asic-e+zip"/>
 * 			<manifest:file-entry manifest:full-path="test.txt" manifest:media-type="text/plain"/>
 * 			<manifest:file-entry manifest:full-path="test-data-file.bin" manifest:media-type="application/octet-stream"/>
 * 		</manifest:manifest>
 * </pre>
 * </code>
 *
 */
public class ASiCEWithXAdESManifestBuilder {

	private final List<DSSDocument> documents;

	public ASiCEWithXAdESManifestBuilder(List<DSSDocument> documents) {
		this.documents = documents;
	}

	public Document build() {
		final Document documentDom = DomUtils.buildDOM();
		final Element manifestDom = documentDom.createElementNS(ManifestNamespace.NS, ManifestNamespace.MANIFEST);
		manifestDom.setAttribute(ManifestNamespace.VERSION, "1.2");
		documentDom.appendChild(manifestDom);

		final Element rootDom = DomUtils.addElement(documentDom, manifestDom, ManifestNamespace.NS, ManifestNamespace.FILE_ENTRY);
		rootDom.setAttribute(ManifestNamespace.FULL_PATH, "/");
		rootDom.setAttribute(ManifestNamespace.MEDIA_TYPE, MimeType.ASICE.getMimeTypeString());

		for (DSSDocument document : documents) {
			Element fileDom = DomUtils.addElement(documentDom, manifestDom, ManifestNamespace.NS, ManifestNamespace.FILE_ENTRY);
			fileDom.setAttribute(ManifestNamespace.FULL_PATH, document.getName());
			fileDom.setAttribute(ManifestNamespace.MEDIA_TYPE, document.getMimeType().getMimeTypeString());
		}

		return documentDom;
	}

}
