package eu.europa.esig.dss.client.http;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class allows to avoid downloading resources.
 */
public class IgnoreDataLoader implements DataLoader {

	private static final long serialVersionUID = -1808691070503805042L;

	private static final Logger LOG = LoggerFactory.getLogger(IgnoreDataLoader.class);

	@Override
	public byte[] get(String url) {
		LOG.debug("Url '{}' is ignored", url);
		return null;
	}

	@Override
	public DataAndUrl get(List<String> urlStrings) {
		LOG.debug("Urls {} are ignored", urlStrings);
		return null;
	}

	@Override
	public byte[] get(String url, boolean refresh) {
		LOG.debug("Url '{}' is ignored", url);
		return null;
	}

	@Override
	public byte[] post(String url, byte[] content) {
		LOG.debug("Url '{}' is ignored", url);
		return null;
	}

	@Override
	public void setContentType(String contentType) {
	}

}
