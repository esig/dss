package eu.europa.esig.dss;

import javax.xml.transform.ErrorListener;
import javax.xml.transform.TransformerException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DSSXmlErrorListener implements ErrorListener {

	private static final Logger logger = LoggerFactory.getLogger(DSSXmlErrorListener.class);

	@Override
	public void warning(TransformerException e) throws TransformerException {
		logger.warn(e.getMessage(), e);
		throw e;
	}

	@Override
	public void error(TransformerException e) throws TransformerException {
		logger.error(e.getMessage(), e);
		throw e;
	}

	@Override
	public void fatalError(TransformerException e) throws TransformerException {
		logger.error(e.getMessage(), e);
		throw e;
	}

}
