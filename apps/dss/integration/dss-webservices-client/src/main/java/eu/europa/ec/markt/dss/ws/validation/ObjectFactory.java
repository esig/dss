
package eu.europa.ec.markt.dss.ws.validation;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the eu.europa.ec.markt.dss.ws.validation package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _ValidateDocumentResponse_QNAME = new QName("http://ws.dss.markt.ec.europa.eu/", "validateDocumentResponse");
    private final static QName _DSSException_QNAME = new QName("http://ws.dss.markt.ec.europa.eu/", "DSSException");
    private final static QName _ValidateDocument_QNAME = new QName("http://ws.dss.markt.ec.europa.eu/", "validateDocument");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: eu.europa.ec.markt.dss.ws.validation
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link WsValidationReport }
     * 
     */
    public WsValidationReport createWsValidationReport() {
        return new WsValidationReport();
    }

    /**
     * Create an instance of {@link ValidateDocumentResponse }
     * 
     */
    public ValidateDocumentResponse createValidateDocumentResponse() {
        return new ValidateDocumentResponse();
    }

    /**
     * Create an instance of {@link WsDocument }
     * 
     */
    public WsDocument createWsDocument() {
        return new WsDocument();
    }

    /**
     * Create an instance of {@link DSSException }
     * 
     */
    public DSSException createDSSException() {
        return new DSSException();
    }

    /**
     * Create an instance of {@link ValidateDocument }
     * 
     */
    public ValidateDocument createValidateDocument() {
        return new ValidateDocument();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link ValidateDocumentResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.dss.markt.ec.europa.eu/", name = "validateDocumentResponse")
    public JAXBElement<ValidateDocumentResponse> createValidateDocumentResponse(ValidateDocumentResponse value) {
        return new JAXBElement<ValidateDocumentResponse>(_ValidateDocumentResponse_QNAME, ValidateDocumentResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link DSSException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.dss.markt.ec.europa.eu/", name = "DSSException")
    public JAXBElement<DSSException> createDSSException(DSSException value) {
        return new JAXBElement<DSSException>(_DSSException_QNAME, DSSException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link ValidateDocument }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.dss.markt.ec.europa.eu/", name = "validateDocument")
    public JAXBElement<ValidateDocument> createValidateDocument(ValidateDocument value) {
        return new JAXBElement<ValidateDocument>(_ValidateDocument_QNAME, ValidateDocument.class, null, value);
    }

}
