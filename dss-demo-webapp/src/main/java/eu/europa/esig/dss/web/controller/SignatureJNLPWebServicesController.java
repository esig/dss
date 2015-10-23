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
package eu.europa.esig.dss.web.controller;

import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import eu.europa.esig.dss.web.service.FreemarkerService;

@Controller
public class SignatureJNLPWebServicesController {

	@Autowired
	private FreemarkerService freemarkerService;

	@RequestMapping(value = "/dss-signature.jnlp", method = RequestMethod.GET)
	public void getJnlp(HttpServletResponse resp) throws Exception {
		resp.setContentType("application/x-java-jnlp-file");
		resp.setCharacterEncoding("UTF-8");
		Writer writer = new OutputStreamWriter(resp.getOutputStream(), Charset.forName("UTF-8"));
		freemarkerService.generateJNLP(writer);
	}

	@RequestMapping(value="/signature-jnlp-webservices", method= RequestMethod.GET)
	public String getInfo() {
		return "jnlp-webservice-intro";
	}

}
