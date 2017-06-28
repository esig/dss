package eu.europa.esig.dss.asic.signature.asice;

import javax.xml.crypto.dsig.XMLSignature;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.asic.ASiCNamespace;

public abstract class AbstractManifestBuilder {

	protected void addSigReference(final Document documentDom, final Element asicManifestDom, String uri, MimeType mimeType) {
		final Element sigReferenceDom = DomUtils.addElement(documentDom, asicManifestDom, ASiCNamespace.NS, ASiCNamespace.SIG_REFERENCE);
		sigReferenceDom.setAttribute("URI", uri);
		sigReferenceDom.setAttribute("MimeType", mimeType.getMimeTypeString());
	}

	protected void addDataObjectReference(final Document documentDom, final Element asicManifestDom, DSSDocument document, DigestAlgorithm digestAlgorithm) {
		final Element dataObjectReferenceDom = DomUtils.addElement(documentDom, asicManifestDom, ASiCNamespace.NS, ASiCNamespace.DATA_OBJECT_REFERENCE);
		dataObjectReferenceDom.setAttribute("URI", document.getName());

		MimeType mimeType = document.getMimeType();
		if (mimeType != null) {
			dataObjectReferenceDom.setAttribute("MimeType", mimeType.getMimeTypeString());
		}

		final Element digestMethodDom = DomUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestMethod");
		digestMethodDom.setAttribute("Algorithm", digestAlgorithm.getXmlId());

		final Element digestValueDom = DomUtils.addElement(documentDom, dataObjectReferenceDom, XMLSignature.XMLNS, "DigestValue");
		final Text textNode = documentDom.createTextNode(document.getDigest(digestAlgorithm));
		digestValueDom.appendChild(textNode);
	}

}
