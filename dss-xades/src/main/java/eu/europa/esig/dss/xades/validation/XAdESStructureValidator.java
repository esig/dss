package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.xades.XAdES111Utils;
import eu.europa.esig.xades.XAdES122Utils;
import eu.europa.esig.xades.XAdES319132Utils;
import org.w3c.dom.Element;

import javax.xml.transform.dom.DOMSource;
import java.util.List;

/**
 * This class is used to validate a structure of a XAdES signature against a corresponding XSD
 *
 */
public class XAdESStructureValidator {

    /** ds:Signature element to validate structure for */
    private final Element signatureElement;

    /** The corresponding XAdES path */
    private final XAdESPath xadesPath;

    /** Cached list of validation errors */
    private List<String> errors;

    /**
     * Default constructor
     *
     * @param signatureElement {@link Element} representing a ds:Signature
     * @param xadesPath {@link XAdESPath} defining the format of XAdES signature
     */
    protected XAdESStructureValidator(final Element signatureElement, final XAdESPath xadesPath) {
        this.signatureElement = signatureElement;
        this.xadesPath = xadesPath;
    }

    /**
     * Validates the signature against corresponding XSD and returns whether the signature has a valid XML structure
     *
     * @return TRUE if the signature XML element passes the validation, FALSE otherwise
     */
    public boolean validate() {
        errors = DSSXMLUtils.validateAgainstXSD(getUtils(xadesPath), new DOMSource(signatureElement));
        return Utils.isCollectionEmpty(errors);
    }

    /**
     * Returns validation errors
     * WARN: The method {@code #validate} shall be executed before
     *
     * @return a list of {@link String} validation errors
     */
    public List<String> getValidationErrors() {
        if (errors == null) {
            throw new IllegalStateException("The method XAdESStructureValidator#validate shall be executed " +
                    "before accessing the validation messages!");
        }
        return errors;
    }

    /**
     * Gets a XAdES implementation of {@code eu.europa.esig.dss.jaxb.common.XSDAbstractUtils}
     * corresponding to the given {@code eu.europa.esig.dss.xades.definition.XAdESPath}
     *
     * @param xadesPath {@link XAdESPath}
     * @return {@link XSDAbstractUtils}
     */
    protected XSDAbstractUtils getUtils(XAdESPath xadesPath) {
        DSSNamespace namespace = xadesPath.getNamespace();
        if (XAdESNamespace.XADES_111 == namespace) {
            return XAdES111Utils.getInstance();
        } else if (XAdESNamespace.XADES_122 == namespace) {
            return XAdES122Utils.getInstance();
        } else if (XAdESNamespace.XADES_132 == namespace || XAdESNamespace.XADES_141 == namespace) {
            return XAdES319132Utils.getInstance();
        } else {
            throw new UnsupportedOperationException(String.format(
                    "The namespace '%s' is not supported for structure validation!", namespace.getUri()));
        }
    }

}
