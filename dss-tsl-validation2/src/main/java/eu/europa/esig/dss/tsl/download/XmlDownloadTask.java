package eu.europa.esig.dss.tsl.download;

import java.util.function.Supplier;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.w3c.dom.Document;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.xades.DSSXMLUtils;

public class XmlDownloadTask implements Supplier<XmlDownloadResult> {

	private final DataLoader dataLoader;
	private final String url;

	public XmlDownloadTask(DataLoader dataLoader, String url) {
		this.dataLoader = dataLoader;
		this.url = url;
	}

	@Override
	public XmlDownloadResult get() {
		try {
			final byte[] content = dataLoader.get(url); // TODO: create DocumentCreator
			final Document dom = DomUtils.buildDOM(content);
			final byte[] canonicalizedContent = DSSXMLUtils.canonicalizeOrSerializeSubtree(CanonicalizationMethod.EXCLUSIVE, dom);
			return new XmlDownloadResult(url, new InMemoryDocument(content), new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, canonicalizedContent)));
		} catch (Exception e) {
			throw new DSSException(String.format("Unable to retieve the content for url '%s'", url), e);
		}
	}

}
