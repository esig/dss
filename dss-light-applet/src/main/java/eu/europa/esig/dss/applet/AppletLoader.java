package eu.europa.esig.dss.applet;

import javax.swing.JApplet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.SignatureTokenType;

@SuppressWarnings("serial")
public class AppletLoader extends JApplet {

	private static final Logger logger = LoggerFactory.getLogger(AppletLoader.class);

	private static final String PARAMETER_OPERATION = "operation";
	private static final String PARAMETER_TOKEN = "token";

	private SignatureTokenType tokenType;
	private Operation operation;

	@Override
	public void init() {
		super.init();
		initParameters();
		logger.info("Applet is correctly initialized with " + PARAMETER_OPERATION + "=" + operation + " and " + PARAMETER_TOKEN + "=" + tokenType);




	}

	/**
	 * This method load required parameters
	 */
	private void initParameters() {
		String parameterOperation = getParameter(PARAMETER_OPERATION);
		if (parameterOperation != null) {
			operation = Operation.valueOf(parameterOperation);
		}

		String parameterToken = getParameter(PARAMETER_TOKEN);
		if (parameterToken != null) {
			tokenType = SignatureTokenType.valueOf(parameterToken);
		}

		if (operation == null) {
			throw new RuntimeException("Unable to retrieve '" + PARAMETER_OPERATION + "' parameter (" + parameterOperation + ")");
		}

		if (tokenType == null) {
			throw new RuntimeException("Unable to retrieve  '" + PARAMETER_TOKEN + "' parameter (" + parameterToken + ")");
		}
	}

}
