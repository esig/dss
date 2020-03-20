package eu.europa.esig.dss.alert.detector;

/**
 * The default Detector for DSSExceptionAlert
 * 
 */
public class ExceptionDetector implements AlertDetector<Exception> {

	@Override
	public boolean detect(Exception e) {
		return e != null;
	}

}
