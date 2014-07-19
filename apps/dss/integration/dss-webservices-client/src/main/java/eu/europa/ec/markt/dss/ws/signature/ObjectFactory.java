package eu.europa.ec.markt.dss.ws.signature;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;

/**
 * This object contains factory methods for each
 * Java content interface and Java element interface
 * generated in the eu.europa.ec.markt.dss.ws.signature package.
 * <p>An ObjectFactory allows you to programatically
 * construct new instances of the Java representation
 * for XML content. The Java representation of XML
 * content can consist of schema derived interfaces
 * and classes representing the binding of schema
 * type definitions, element declarations and model
 * groups.  Factory methods for each of these are
 * provided in this class.
 */
@XmlRegistry
public class ObjectFactory {

	private final static QName _SignDocument_QNAME = new QName("http://ws.dss.markt.ec.europa.eu/", "signDocument");
	private final static QName _ExtendSignature_QNAME = new QName("http://ws.dss.markt.ec.europa.eu/", "extendSignature");
	private final static QName _DSSException_QNAME = new QName("http://ws.dss.markt.ec.europa.eu/", "DSSException");
	private final static QName _GetDataToSignResponse_QNAME = new QName("http://ws.dss.markt.ec.europa.eu/", "getDataToSignResponse");
	private final static QName _SignDocumentResponse_QNAME = new QName("http://ws.dss.markt.ec.europa.eu/", "signDocumentResponse");
	private final static QName _GetDataToSign_QNAME = new QName("http://ws.dss.markt.ec.europa.eu/", "getDataToSign");
	private final static QName _ExtendSignatureResponse_QNAME = new QName("http://ws.dss.markt.ec.europa.eu/", "extendSignatureResponse");

	/**
	 * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: eu.europa.ec.markt.dss.ws.signature
	 */
	public ObjectFactory() {
	}

	/**
	 * Create an instance of {@link WsParameters }
	 */
	public WsParameters createWsParameters() {
		return new WsParameters();
	}

	/**
	 * Create an instance of {@link SignDocument }
	 */
	public SignDocument createSignDocument() {
		return new SignDocument();
	}

	/**
	 * Create an instance of {@link ExtendSignature }
	 */
	public ExtendSignature createExtendSignature() {
		return new ExtendSignature();
	}

	/**
	 * Create an instance of {@link SignerLocation }
	 */
	public SignerLocation createSignerLocation() {
		return new SignerLocation();
	}

	/**
	 * Create an instance of {@link DssTransform }
	 */
	public DssTransform createDssTransform() {
		return new DssTransform();
	}

	/**
	 * Create an instance of {@link WsDocument }
	 */
	public WsDocument createWsDocument() {
		return new WsDocument();
	}

	/**
	 * Create an instance of {@link DssReference }
	 */
	public DssReference createDssReference() {
		return new DssReference();
	}

	/**
	 * Create an instance of {@link Policy }
	 */
	public Policy createPolicy() {
		return new Policy();
	}

	/**
	 * Create an instance of {@link GetDataToSignResponse }
	 */
	public GetDataToSignResponse createGetDataToSignResponse() {
		return new GetDataToSignResponse();
	}

	/**
	 * Create an instance of {@link DSSException }
	 */
	public DSSException createDSSException() {
		return new DSSException();
	}

	/**
	 * Create an instance of {@link ExtendSignatureResponse }
	 */
	public ExtendSignatureResponse createExtendSignatureResponse() {
		return new ExtendSignatureResponse();
	}

	/**
	 * Create an instance of {@link GetDataToSign }
	 */
	public GetDataToSign createGetDataToSign() {
		return new GetDataToSign();
	}

	/**
	 * Create an instance of {@link SignDocumentResponse }
	 */
	public SignDocumentResponse createSignDocumentResponse() {
		return new SignDocumentResponse();
	}

	/**
	 * Create an instance of {@link JAXBElement }{@code <}{@link SignDocument }{@code >}}
	 */
	@XmlElementDecl(namespace = "http://ws.dss.markt.ec.europa.eu/", name = "signDocument")
	public JAXBElement<SignDocument> createSignDocument(SignDocument value) {
		return new JAXBElement<SignDocument>(_SignDocument_QNAME, SignDocument.class, null, value);
	}

	/**
	 * Create an instance of {@link JAXBElement }{@code <}{@link ExtendSignature }{@code >}}
	 */
	@XmlElementDecl(namespace = "http://ws.dss.markt.ec.europa.eu/", name = "extendSignature")
	public JAXBElement<ExtendSignature> createExtendSignature(ExtendSignature value) {
		return new JAXBElement<ExtendSignature>(_ExtendSignature_QNAME, ExtendSignature.class, null, value);
	}

	/**
	 * Create an instance of {@link JAXBElement }{@code <}{@link DSSException }{@code >}}
	 */
	@XmlElementDecl(namespace = "http://ws.dss.markt.ec.europa.eu/", name = "DSSException")
	public JAXBElement<DSSException> createDSSException(DSSException value) {
		return new JAXBElement<DSSException>(_DSSException_QNAME, DSSException.class, null, value);
	}

	/**
	 * Create an instance of {@link JAXBElement }{@code <}{@link GetDataToSignResponse }{@code >}}
	 */
	@XmlElementDecl(namespace = "http://ws.dss.markt.ec.europa.eu/", name = "getDataToSignResponse")
	public JAXBElement<GetDataToSignResponse> createGetDataToSignResponse(GetDataToSignResponse value) {
		return new JAXBElement<GetDataToSignResponse>(_GetDataToSignResponse_QNAME, GetDataToSignResponse.class, null, value);
	}

	/**
	 * Create an instance of {@link JAXBElement }{@code <}{@link SignDocumentResponse }{@code >}}
	 */
	@XmlElementDecl(namespace = "http://ws.dss.markt.ec.europa.eu/", name = "signDocumentResponse")
	public JAXBElement<SignDocumentResponse> createSignDocumentResponse(SignDocumentResponse value) {
		return new JAXBElement<SignDocumentResponse>(_SignDocumentResponse_QNAME, SignDocumentResponse.class, null, value);
	}

	/**
	 * Create an instance of {@link JAXBElement }{@code <}{@link GetDataToSign }{@code >}}
	 */
	@XmlElementDecl(namespace = "http://ws.dss.markt.ec.europa.eu/", name = "getDataToSign")
	public JAXBElement<GetDataToSign> createGetDataToSign(GetDataToSign value) {
		return new JAXBElement<GetDataToSign>(_GetDataToSign_QNAME, GetDataToSign.class, null, value);
	}

	/**
	 * Create an instance of {@link JAXBElement }{@code <}{@link ExtendSignatureResponse }{@code >}}
	 */
	@XmlElementDecl(namespace = "http://ws.dss.markt.ec.europa.eu/", name = "extendSignatureResponse")
	public JAXBElement<ExtendSignatureResponse> createExtendSignatureResponse(ExtendSignatureResponse value) {
		return new JAXBElement<ExtendSignatureResponse>(_ExtendSignatureResponse_QNAME, ExtendSignatureResponse.class, null, value);
	}

}
