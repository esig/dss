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
package eu.europa.esig.xmldsig;

import eu.europa.esig.dss.xml.common.ValidatorConfigurator;
import eu.europa.esig.dss.xml.common.XmlDefinerUtils;
import eu.europa.esig.dss.xml.common.alert.DSSErrorHandlerAlert;
import eu.europa.esig.dss.xml.common.exception.XSDValidationException;
import eu.europa.esig.xmldsig.jaxb.SignatureType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XmlDSigUtilsTest {
	
	private static XmlDSigUtils xmlDSigUtils;
	
	private static StreamSource aliceFile;

	private static StreamSource bobFile;

	@BeforeAll
	public static void init() {
		xmlDSigUtils = XmlDSigUtils.getInstance();

		aliceFile = new StreamSource(new File("src/test/resources/XmlAliceSig.xml"));
		bobFile = new StreamSource(new File("src/test/resources/XmlBobSig.xml"));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void test() throws JAXBException, SAXException {

		File xmldsigFile = new File("src/test/resources/XmlAliceSig.xml");

		JAXBContext jc = xmlDSigUtils.getJAXBContext();
		assertNotNull(jc);

		Schema schema = xmlDSigUtils.getSchema();
		assertNotNull(schema);

		Unmarshaller unmarshaller = jc.createUnmarshaller();
		unmarshaller.setSchema(schema);

		JAXBElement<SignatureType> unmarshalled = (JAXBElement<SignatureType>) unmarshaller.unmarshal(xmldsigFile);
		assertNotNull(unmarshalled);

		Marshaller marshaller = jc.createMarshaller();
		marshaller.setSchema(schema);

		StringWriter sw = new StringWriter();
		marshaller.marshal(unmarshalled, sw);

		String xmldsigString = sw.toString();

		JAXBElement<SignatureType> unmarshalled2 = (JAXBElement<SignatureType>) unmarshaller.unmarshal(new StringReader(xmldsigString));
		assertNotNull(unmarshalled2);
	}

	@Test
	public void getJAXBContext() throws JAXBException {
		assertNotNull(xmlDSigUtils.getJAXBContext());
		// cached
		assertNotNull(xmlDSigUtils.getJAXBContext());
	}

	@Test
	public void getSchema() throws SAXException {
		assertNotNull(xmlDSigUtils.getSchema());
		// cached
		assertNotNull(xmlDSigUtils.getSchema());
	}

	@Test
	public void defaultConfigTest() throws IOException, SAXException {
		xmlDSigUtils.validate(aliceFile, xmlDSigUtils.getSchema(), true);

		XSDValidationException exception = assertThrows(XSDValidationException.class,
				() -> xmlDSigUtils.validate(bobFile, xmlDSigUtils.getSchema(), true));
		assertNotNull(exception.getMessage());

		List<String> allMessages = exception.getAllMessages();
		assertNotNull(allMessages);
		assertEquals(2, allMessages.size());

		Throwable[] suppressed = exception.getSuppressed();
		assertEquals(2, suppressed.length);

		List<String> xsdValidationMessages = xmlDSigUtils.validateAgainstXSD(bobFile);
		assertEquals(2, xsdValidationMessages.size());
		assertEquals(allMessages, xsdValidationMessages);
	}

	@Test
	public void dssErrorHandlerPositionTest() {
		DSSErrorHandlerAlert dssErrorHandlerAlert = new DSSErrorHandlerAlert();

		ValidatorConfigurator validatorConfigurator = ValidatorConfigurator.getSecureValidatorConfigurator();
		validatorConfigurator.setErrorHandlerAlert(dssErrorHandlerAlert);

		dssErrorHandlerAlert.setEnablePosition(false);

		XmlDefinerUtils.getInstance().setValidatorConfigurator(validatorConfigurator);

		XSDValidationException exception = assertThrows(XSDValidationException.class,
				() -> xmlDSigUtils.validate(bobFile, xmlDSigUtils.getSchema(), true));

		String completeMessage = exception.getMessage();
		assertNotNull(completeMessage);

		List<String> messagesNoPosition = exception.getAllMessages();
		assertNotNull(messagesNoPosition);
		assertEquals(2, messagesNoPosition.size());
		for (String message : messagesNoPosition) {
			assertTrue(completeMessage.contains(message));
			assertFalse(message.contains("Line"));
			assertFalse(message.contains("Column"));
		}

		dssErrorHandlerAlert.setEnablePosition(true);

		exception = assertThrows(XSDValidationException.class,
				() -> xmlDSigUtils.validate(bobFile, xmlDSigUtils.getSchema(), true));

		completeMessage = exception.getMessage();
		assertNotNull(completeMessage);

		List<String> messagesWithPosition = exception.getAllMessages();
		assertNotNull(messagesWithPosition);
		assertEquals(2, messagesWithPosition.size());
		for (String message : messagesWithPosition) {
			assertTrue(completeMessage.contains(message));
			assertTrue(message.contains("Line"));
			assertTrue(message.contains("Column"));
		}

		assertTrue(messagesWithPosition.get(0).contains(messagesNoPosition.get(0)));
		assertTrue(messagesWithPosition.get(1).contains(messagesNoPosition.get(1)));
	}

	@Test
	public void customAlertWithRuntimeExceptionTest() {
		ValidatorConfigurator validatorConfigurator = ValidatorConfigurator.getSecureValidatorConfigurator();
		validatorConfigurator.setErrorHandlerAlert(errorHandler -> {
			if (!errorHandler.isValid()) {
				throw new RuntimeException(errorHandler.getErrors().iterator().next());
			}
		});
		XmlDefinerUtils.getInstance().setValidatorConfigurator(validatorConfigurator);
		assertThrows(RuntimeException.class, () -> xmlDSigUtils.validate(bobFile, xmlDSigUtils.getSchema(), true));
	}

	@Test
	public void customAlertSilenceTest() throws IOException, SAXException {
		ValidatorConfigurator validatorConfigurator = ValidatorConfigurator.getSecureValidatorConfigurator();

		validatorConfigurator.setErrorHandlerAlert(errorHandler -> {
			// do nothing
		});

		XmlDefinerUtils.getInstance().setValidatorConfigurator(validatorConfigurator);
		xmlDSigUtils.validate(bobFile, xmlDSigUtils.getSchema(), true);
	}

	@AfterEach
	public void reset() {
		ValidatorConfigurator secureValidatorConfigurator = ValidatorConfigurator.getSecureValidatorConfigurator();
		XmlDefinerUtils.getInstance().setValidatorConfigurator(secureValidatorConfigurator);
	}

}
