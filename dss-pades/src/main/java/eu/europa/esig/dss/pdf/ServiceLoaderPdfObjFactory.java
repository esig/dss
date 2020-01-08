package eu.europa.esig.dss.pdf;

import java.util.Iterator;
import java.util.ServiceLoader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of IPdfObjFactory which looks for in the registered services and uses the first found instance.
 * 
 * This class is not registered as service.
 */
public class ServiceLoaderPdfObjFactory implements IPdfObjFactory {

	private static final Logger LOG = LoggerFactory.getLogger(ServiceLoaderPdfObjFactory.class);

	@Override
	public PDFSignatureService newPAdESSignatureService() {
		return getIPdfObjFactory().newPAdESSignatureService();
	}

	@Override
	public PDFSignatureService newContentTimestampService() {
		return getIPdfObjFactory().newContentTimestampService();
	}

	@Override
	public PDFSignatureService newSignatureTimestampService() {
		return getIPdfObjFactory().newSignatureTimestampService();
	}

	@Override
	public PDFSignatureService newArchiveTimestampService() {
		return getIPdfObjFactory().newArchiveTimestampService();
	}

	private IPdfObjFactory getIPdfObjFactory() {
		ServiceLoader<IPdfObjFactory> loader = ServiceLoader.load(IPdfObjFactory.class);
		Iterator<IPdfObjFactory> iterator = loader.iterator();
		if (!iterator.hasNext()) {
			throw new ExceptionInInitializerError(
					"No implementation found for IPdfObjFactory in classpath, please choose between modules 'dss-pades-pdfbox' or 'dss-pades-openpdf'");
		}
		IPdfObjFactory instance = iterator.next();
		LOG.debug("Current instance of IPdfObjFactory : {}", instance.getClass().getSimpleName());
		return instance;
	}

}
