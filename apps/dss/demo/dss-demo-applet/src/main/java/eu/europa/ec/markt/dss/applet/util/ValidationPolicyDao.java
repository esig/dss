/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.applet.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.sun.xml.xsom.XSAttributeDecl;
import com.sun.xml.xsom.XSAttributeUse;
import com.sun.xml.xsom.XSComplexType;
import com.sun.xml.xsom.XSContentType;
import com.sun.xml.xsom.XSElementDecl;
import com.sun.xml.xsom.XSModelGroup;
import com.sun.xml.xsom.XSParticle;
import com.sun.xml.xsom.XSSchema;
import com.sun.xml.xsom.XSSchemaSet;
import com.sun.xml.xsom.XSTerm;
import com.sun.xml.xsom.impl.ComplexTypeImpl;
import com.sun.xml.xsom.parser.XSOMParser;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ValidationPolicyDao {

	private URL xmlUrl;
	private URL xsdUrl;

	public URL getXmlUrl() {
		return xmlUrl;
	}

	public URL getXsdUrl() {
		return xsdUrl;
	}

	public ValidationPolicy load(URL url, URL xsdUrl) {
		try {
			this.xmlUrl = url;
			this.xsdUrl = xsdUrl;
			return load(url.openStream(), xsdUrl.openStream());
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public ValidationPolicy load(InputStream inputStream, InputStream xsdInputStream) throws DSSException {
		//To clone inputStream
		byte[] fileInputStream = cloneFileInputStream(inputStream);
		InputStream inputStreamClone2 = new ByteArrayInputStream(fileInputStream);

		byte[] fileInputStreamXsd = cloneFileInputStream(xsdInputStream);
		InputStream xsdStream1 = new ByteArrayInputStream(fileInputStreamXsd);
		InputSource sourceentree = new InputSource(xsdStream1);

		HashMap<String, Object> xsdTree = getXsdElements();

		final Document document = DSSXMLUtils.buildDOM(inputStreamClone2);

		//Clean XML
		XPath xp = XPathFactory.newInstance().newXPath();
		NodeList nl = null;
		try {
			nl = (NodeList) xp.evaluate("//text()[normalize-space(.)='']", document, XPathConstants.NODESET);
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
		for (int i = 0; i < nl.getLength(); ++i) {
			Node node = nl.item(i);
			node.getParentNode().removeChild(node);
		}
		document.normalizeDocument();
		document.normalize();

		final XmlDom xmlDom = new XmlDom(document);
		final ValidationPolicy validationPolicy = new ValidationPolicy(xmlDom, xsdUrl, xsdTree, document);

		return validationPolicy;
	}

	private byte[] cloneFileInputStream(InputStream inputStream) {
		//To clone inputStream
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buf = new byte[1024];
		int n = 0;
		try {
			while ((n = inputStream.read(buf)) >= 0) {
				baos.write(buf, 0, n);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		byte[] content = baos.toByteArray();
		return baos.toByteArray();
	}

	/**
	 * Get XSD schema in hashMap tree
	 *
	 * @return HashMap<String, Object>
	 */
	public HashMap<String, Object> getXsdElements() {
		XSSchema schemaSet = loadXsd();
		//---
		HashMap<String, Object> hmReturned = new HashMap<String, Object>();
		HashMap<String, Object> hm = new HashMap<String, Object>();
		Iterator<XSElementDecl> itre = schemaSet.iterateElementDecls();
		//---
		while (itre.hasNext()) {
			XSElementDecl xse = (XSElementDecl) itre.next();

			hmReturned.put(xse.getName(), hm);
			XSComplexType xscomp = xse.getType().asComplexType();
			if (xscomp != null) {
				XSContentType xscont = xscomp.getContentType();
				XSParticle particle = xscont.asParticle();
				getElementsRecursively(hm, particle);
			}
		}
		return hmReturned;
	}

	/*
	 * recursive helper method of getXmlElements
	 * note that since we don't know the "deepness" of the
	 * schema a recursive way of implementation was necessary
	 */
	private void getElementsRecursively(HashMap<String, Object> hm, XSParticle xsp) {
		if (xsp != null) {
			XSTerm term = xsp.getTerm();
			if (term.isElementDecl()) {
				XSComplexType xscmp = (term.asElementDecl()).getType().asComplexType();
				//---
				if (xscmp == null) {
					if (xsp.getMinOccurs() == BigInteger.valueOf(0)) {
						if (xsp.getMaxOccurs() != BigInteger.valueOf(-1)) {
							hm.put(term.asElementDecl().getName(), "|");
						} else {
							hm.put(term.asElementDecl().getName(), "|n");
						}
					} else {
						hm.put(term.asElementDecl().getName(), "=");
					}
				} else {
					XSContentType xscont = xscmp.getContentType();
					XSParticle particle = xscont.asParticle();
					HashMap<String, Object> newHm = new HashMap<String, Object>();

					//Attributes
					Collection<? extends XSAttributeUse> attributeList = xscmp.getAttributeUses();
					Iterator<? extends XSAttributeUse> itAttr = attributeList.iterator();
					while (itAttr.hasNext()) {
						XSAttributeUse attr = itAttr.next();
						XSAttributeDecl attrInfo = attr.getDecl();
						newHm.put(attrInfo.getName(), null);
					}

					getElementsRecursively(newHm, particle);

					//TODO do better
					if (((ComplexTypeImpl) xscmp).getType().getBaseType().getName().equalsIgnoreCase("string")) {
						//Can element appears several times?
						if (xsp.getMaxOccurs() != BigInteger.valueOf(-1)) {
							//Text node : no children
							newHm.put(term.asElementDecl().getName(), "TEXT");
						} else {
							newHm.put(term.asElementDecl().getName(), "NTEXT");
						}

					}
					hm.put(term.asElementDecl().getName(), newHm);


				}
				//---
			} else if (term.isModelGroup()) {
				XSModelGroup model = term.asModelGroup();
				XSParticle[] parr = model.getChildren();
				for (XSParticle partemp : parr) {
					getElementsRecursively(hm, partemp);
				}
			}
		}
	}

	/**
	 * Load xsd from file .xsd
	 *
	 * @return XSOM.XSSchema
	 */
	private XSSchema loadXsd() {
		XSOMParser parser = new XSOMParser();
		XSSchemaSet xsSchemaSet = null;
		try {
			//			System.out.println("##########" + xsdUrl.toString());
			parser.parse(xsdUrl.openStream());
			xsSchemaSet = parser.getResult();

		} catch (Exception e) {
			e.printStackTrace();
		}
		Object[] schemaArray = xsSchemaSet.getSchemas().toArray();
		XSSchema s = null;
		if (schemaArray.length > 1) {
			s = (XSSchema) xsSchemaSet.getSchemas().toArray()[1];
		}
		return s;
	}

	public void save(ValidationPolicy validationPolicy, OutputStream outputStream) {
		Transformer transformer = null;
		try {
			transformer = TransformerFactory.newInstance().newTransformer();
			Result output = new StreamResult(outputStream);
			Source input = new DOMSource(validationPolicy.getDocument());

			transformer.transform(input, output);
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		}

	}
}
