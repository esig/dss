package eu.europa.esig.dss.xades;

import javax.xml.transform.ErrorListener;
import javax.xml.transform.TransformerException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DSSXmlErrorListener implements ErrorListener {

	private static final Logger logger = LoggerFactory.getLogger(DSSXmlErrorListener.class);

	@Override
	public void warning(TransformerException exception) throws TransformerException {
		logger.warn(exception.getMessage(), exception);
	}

	@Override
	public void error(TransformerException exception) throws TransformerException {
		logger.error(exception.getMessage(), exception);

	}

	@Override
	public void fatalError(TransformerException exception) throws TransformerException {
		logger.error(exception.getMessage(), exception);
	}

}
