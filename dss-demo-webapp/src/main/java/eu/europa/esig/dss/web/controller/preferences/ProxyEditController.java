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
package eu.europa.esig.dss.web.controller.preferences;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.request.WebRequest;

import eu.europa.esig.dss.client.http.proxy.ProxyKey;
import eu.europa.esig.dss.client.http.proxy.ProxyPreference;
import eu.europa.esig.dss.client.http.proxy.ProxyPreferenceManager;
import eu.europa.esig.dss.web.model.PreferenceForm;

/**
 * Controller for proxi edition
 */
@Controller
@RequestMapping(value = "/admin/proxy")
public class ProxyEditController {

	private static final Logger logger = LoggerFactory.getLogger(ProxyEditController.class);

	@Autowired
	private ProxyPreferenceManager proxyPreferenceManager;

	/**
	 * @param webRequest
	 *            The web request
	 * @return a proxy form bean
	 */
	@ModelAttribute("preferenceForm")
	public final PreferenceForm setupForm(final WebRequest webRequest) {

		final String requestKey = webRequest.getParameter("key");
		final PreferenceForm form = new PreferenceForm();
		final ProxyKey proxyKey = ProxyKey.fromKey(requestKey);
		final ProxyPreference preference = proxyPreferenceManager.get(proxyKey);

		form.setKey(preference.getProxyKey().getKeyName());
		form.setValue(preference.getValue());

		return form;
	}

	/**
	 * @param model
	 *            The view model
	 * @return a view name
	 */
	@RequestMapping(value = "/edit", method = RequestMethod.GET)
	public String showForm(final Model model) {
		return "admin-proxy-edit";
	}

	/**
	 * @param form
	 *            The proxy form bean
	 * @return a view name
	 */
	@RequestMapping(value = "/edit", method = RequestMethod.POST)
	public String updatePreferences(@ModelAttribute("preferenceForm") final PreferenceForm form) {
		final String proxyKeyString = form.getKey();
		final String proxyValueString = form.getValue();
		proxyPreferenceManager.update(proxyKeyString, proxyValueString);
		logger.trace(">>> Proxy preference updated: " + proxyKeyString + "(" + proxyValueString + ")/" + proxyPreferenceManager);
		return "redirect:/admin/proxy";
	}
}
