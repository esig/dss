package eu.europa.esig.dss.tsl.download;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.tsl.Task;
import eu.europa.esig.dss.xades.DSSXMLUtils;

public class XmlDownloadTask implements Task<XmlDownloadResult> {

	private static final Logger LOG = LoggerFactory.getLogger(XmlDownloadTask.class);

	private final DataLoader dataLoader;
	private final String url;

	public XmlDownloadTask(DataLoader dataLoader, String url) {
		this.dataLoader = dataLoader;
		this.url = url;
	}

	@Override
	public XmlDownloadResult execute() {
		try {
			final byte[] content = dataLoader.get(url);
			final Document dom = DomUtils.buildDOM(content);
			final byte[] canonicalizedContent = DSSXMLUtils.canonicalizeOrSerializeSubtree(CanonicalizationMethod.EXCLUSIVE, dom);
			return new XmlDownloadResult(url, content, new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, canonicalizedContent)));
		} catch (Exception e) {
			LOG.error(String.format("Unable to execute XmlDownloadTask for url '%s'", url), e);
			return null;
		}
	}

}
