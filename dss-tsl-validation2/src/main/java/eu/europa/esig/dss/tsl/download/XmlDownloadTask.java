package eu.europa.esig.dss.tsl.download;

import java.util.function.Supplier;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.w3c.dom.Document;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.service.http.commons.DSSFileLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xades.DSSXMLUtils;

public class XmlDownloadTask implements Supplier<XmlDownloadResult> {

	private final DSSFileLoader dssFileLoader;
	private final String url;

	public XmlDownloadTask(DSSFileLoader dssFileLoader, String url) {
		this.dssFileLoader = dssFileLoader;
		this.url = url;
	}

	@Override
	public XmlDownloadResult get() {
		try {
			final DSSDocument dssDocument = dssFileLoader.getDocument(url);
			final Document dom = DomUtils.buildDOM(dssDocument);
			final byte[] canonicalizedContent = DSSXMLUtils.canonicalizeOrSerializeSubtree(CanonicalizationMethod.EXCLUSIVE, dom);
			return new XmlDownloadResult(dssDocument, new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, canonicalizedContent)));
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to retieve the content for url '%s'. Reason : '%s'", url, e.getMessage()), e);
		}
	}

}
