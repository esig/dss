package eu.europa.esig.dss.web.service;

import java.io.InputStream;
import java.io.StringWriter;

import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.oxm.Marshaller;
import org.springframework.oxm.Unmarshaller;
import org.springframework.stereotype.Component;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

@Component
public class PolicyJaxbService {

	private static final Logger logger = LoggerFactory.getLogger(PolicyJaxbService.class);

	@Autowired
	private Unmarshaller policyUnmarshaller;

	@Autowired
	private Marshaller policyMarshaller;

	public ConstraintsParameters unmarshall(String filePath) {
		InputStream is = null;
		ConstraintsParameters policy = null;
		try {
			is = PolicyJaxbService.class.getResourceAsStream(filePath);
			policy = (ConstraintsParameters) policyUnmarshaller.unmarshal(new StreamSource(is));
		} catch (Exception e) {
			logger.error("Unable to parse '" + filePath + "' : " + e.getMessage(), e);
		} finally {
			Utils.closeQuietly(is);
		}
		return policy;
	}

	/**
	 * This method marshall ConstraintsParameters objects to String
	 * Empty LevelConstraints are disabled/removed with JS
	 */
	public String marshall(ConstraintsParameters constraintsParams) {
		StringWriter writer = new StringWriter();
		try {
			policyMarshaller.marshal(constraintsParams, new StreamResult(writer));
		} catch (Exception e) {
			logger.error("Unable to parse JaxB object : " + e.getMessage(), e);
		}
		return writer.toString();
	}

}
