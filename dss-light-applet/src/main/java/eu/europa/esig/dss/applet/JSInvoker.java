package eu.europa.esig.dss.applet;

import java.applet.Applet;
import java.util.Arrays;

import netscape.javascript.JSObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class allows to interact with the browser and to call javascript methods
 */
public final class JSInvoker {

	private static final Logger logger = LoggerFactory.getLogger(JSInvoker.class);

	private final JSObject jsObject;

	public JSInvoker(Applet applet) {
		this.jsObject = JSObject.getWindow(applet);
	}

	public void injectCertificate(String jsFunctionName, String base64Certificate, String readableCertificate, String encryptionAlgorithm) {
		callMethod(jsFunctionName, base64Certificate, readableCertificate, encryptionAlgorithm);
	}

	public void injectCertificateChain(String jsFunctionName, String base64Certificate, String chainCertificate) {
		callMethod(jsFunctionName, base64Certificate, chainCertificate);
	}

	public void injectSignature(String jsFunction, String base64SignatureValue) {
		callMethod(jsFunction, base64SignatureValue);
	}

	private void callMethod(String jsFunctionName, Object... args) {
		logger.info("Call js function '" + jsFunctionName + "' with arguments : " + Arrays.toString(args));
		jsObject.call(jsFunctionName, args);
	}

}
