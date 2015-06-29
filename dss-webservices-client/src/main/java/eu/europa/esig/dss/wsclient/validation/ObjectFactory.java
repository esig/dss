
/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.wsclient.validation;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each
 * Java content interface and Java element interface
 * generated in the eu.europa.esig.dss.wsclient.validation package.
 *
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

	private final static QName _ValidateDocumentResponse_QNAME = new QName("http://ws.dss.esig.europa.eu/", "validateDocumentResponse");
	private final static QName _DSSException_QNAME = new QName("http://ws.dss.esig.europa.eu/", "DSSException");
	private final static QName _ValidateDocument_QNAME = new QName("http://ws.dss.esig.europa.eu/", "validateDocument");

	/**
	 * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: eu.europa.esig.dss.wsclient.validation
	 *
	 */
	public ObjectFactory() {
	}

	/**
	 * Create an instance of {@link MimeType }
	 *
	 */
	public MimeType createMimeType() {
		return new MimeType();
	}

	/**
	 * Create an instance of {@link ValidateDocument }
	 *
	 */
	public ValidateDocument createValidateDocument() {
		return new ValidateDocument();
	}

	/**
	 * Create an instance of {@link DSSException }
	 *
	 */
	public DSSException createDSSException() {
		return new DSSException();
	}

	/**
	 * Create an instance of {@link WsDocument }
	 *
	 */
	public WsDocument createWsDocument() {
		return new WsDocument();
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
	 * Create an instance of {@link JAXBElement }{@code <}{@link ValidateDocumentResponse }{@code >}}
	 *
	 */
	@XmlElementDecl(namespace = "http://ws.dss.esig.europa.eu/", name = "validateDocumentResponse")
	public JAXBElement<ValidateDocumentResponse> createValidateDocumentResponse(ValidateDocumentResponse value) {
		return new JAXBElement<ValidateDocumentResponse>(_ValidateDocumentResponse_QNAME, ValidateDocumentResponse.class, null, value);
	}

	/**
	 * Create an instance of {@link JAXBElement }{@code <}{@link DSSException }{@code >}}
	 *
	 */
	@XmlElementDecl(namespace = "http://ws.dss.esig.europa.eu/", name = "DSSException")
	public JAXBElement<DSSException> createDSSException(DSSException value) {
		return new JAXBElement<DSSException>(_DSSException_QNAME, DSSException.class, null, value);
	}

	/**
	 * Create an instance of {@link JAXBElement }{@code <}{@link ValidateDocument }{@code >}}
	 *
	 */
	@XmlElementDecl(namespace = "http://ws.dss.esig.europa.eu/", name = "validateDocument")
	public JAXBElement<ValidateDocument> createValidateDocument(ValidateDocument value) {
		return new JAXBElement<ValidateDocument>(_ValidateDocument_QNAME, ValidateDocument.class, null, value);
	}

}
