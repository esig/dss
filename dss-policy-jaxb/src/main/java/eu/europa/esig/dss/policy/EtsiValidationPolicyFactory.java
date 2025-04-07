package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.policy.ValidationPolicyFactory;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import jakarta.xml.bind.JAXBException;
import org.xml.sax.SAXException;

import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Loads a DSS XML Validation Policy based on the ETSI TS 102 853 standard.
 *
 */
public class EtsiValidationPolicyFactory implements ValidationPolicyFactory {

    /** The default validation policy path */
    private static final String DEFAULT_VALIDATION_POLICY_LOCATION = "/policy/constraint.xml";

    /**
     * Default constructor
     */
    public EtsiValidationPolicyFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument validationPolicyDocument) {
        try (InputStream is = validationPolicyDocument.openStream()) {
            ConstraintsParameters constraintsParameters = ValidationPolicyFacade.newFacade().unmarshall(is, false);
            return constraintsParameters != null;
        } catch (IOException | JAXBException | XMLStreamException | SAXException e) {
            return false;
        }
    }

    @Override
    public ValidationPolicy loadDefaultValidationPolicy() {
        try {
            return loadValidationPolicy(EtsiValidationPolicyFactory.class.getResourceAsStream(DEFAULT_VALIDATION_POLICY_LOCATION));
        } catch (Exception e) {
            throw new UnsupportedOperationException(
                    String.format("Unable to load the default policy document. Reason : %s", e.getMessage()), e);
        }
    }

    @Override
    public ValidationPolicy loadValidationPolicy(DSSDocument validationPolicyDocument) {
        return loadValidationPolicy(validationPolicyDocument.openStream());
    }

    @Override
    public ValidationPolicy loadValidationPolicy(InputStream validationPolicyInputStream) {
        try (InputStream is = validationPolicyInputStream) {
            return ValidationPolicyFacade.newFacade().getValidationPolicy(is);
        } catch (Exception e) {
            throw new UnsupportedOperationException(
                    String.format("Unable to load the default policy document. Reason : %s", e.getMessage()), e);
        }
    }

}
