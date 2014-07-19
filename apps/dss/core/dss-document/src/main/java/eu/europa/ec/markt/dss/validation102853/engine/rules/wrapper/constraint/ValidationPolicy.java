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
package eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint;

import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import org.w3c.dom.Document;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.transform.sax.SAXSource;
import java.net.URL;
import java.util.HashMap;

/**
 * In memory representation on the XML Validation Policy Constraint document and XSD
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */

public class ValidationPolicy {
    private Document document;
    XmlDom xmlDom;
    HashMap<String, Object> treeResult;
    private final URL sourceXSD;

    public ValidationPolicy(XmlDom xmlDom, URL sourceXSD, HashMap<String, Object> treeResult, Document document) {
        this.xmlDom = xmlDom;
        this.treeResult = treeResult;
        this.document = document;
        this.sourceXSD = sourceXSD;
    }

    public Document getDocument() {
        return document;
    }

    public XmlDom getXmlDom() {
        return xmlDom;
    }

    public void setXmlDom(XmlDom xmlDom) {
        this.xmlDom = xmlDom;
    }

    public HashMap<String, Object> getTreeResult() {
        return treeResult;
    }

    public URL getSourceXSD() {
        return sourceXSD;
    }
}
