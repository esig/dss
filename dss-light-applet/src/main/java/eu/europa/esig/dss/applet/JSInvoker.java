package eu.europa.esig.dss.applet;

import java.applet.Applet;

import netscape.javascript.JSObject;

/**
 * This class allows to interact with the browser and to call javascript methods
 */
public final class JSInvoker {

	private final JSObject jsObject;

	public JSInvoker(Applet applet) {
		this.jsObject = JSObject.getWindow(applet);
	}

	public void injectCertificate(String jsFunctionName, String base64Certificate, String readableCertificate) {
		callMethod(jsFunctionName, base64Certificate, readableCertificate);
	}

	public void injectSignature(String jsFunction, String base64SignatureValue) {
		callMethod(jsFunction, base64SignatureValue);
	}

	private void callMethod(String jsFunctionName, Object... args) {
		jsObject.call(jsFunctionName, args);
	}

}
