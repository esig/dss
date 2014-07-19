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
package eu.europa.ec.markt.dss.web.controller;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.dao.PreferencesDao;
import eu.europa.ec.markt.dss.model.Preference;
import eu.europa.ec.markt.dss.model.PreferenceKey;
import eu.europa.ec.markt.dss.validation102853.ValidationResourceManager;

/**
 *
 * Signature controller
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
@Controller
@RequestMapping(value = "/signature")
public class SignatureController {
    /**
     * @see PreferencesDao
     */
    @Autowired
    private PreferencesDao preferencesDao;

    /**
     * @param model The model attributes
     * @return a view name
     */
    @RequestMapping(method = RequestMethod.GET)
    public String showSignature(final Model model, HttpServletRequest request) {

        final Preference serviceUrl = preferencesDao.get(PreferenceKey.SERVICE_URL);
        model.addAttribute("prefUrlService", serviceUrl);
        final Preference preference = preferencesDao.get(PreferenceKey.DEFAULT_POLICY_URL);
        if (DSSUtils.isNotBlank(preference.getValue())) {
            final String prefDefaultPolicyUrl = serviceUrl.getValue().replaceAll("service", "signature/policy.xml");
            model.addAttribute("prefDefaultPolicyUrl", prefDefaultPolicyUrl);
        }

        return "signature";
    }

    @RequestMapping(method = RequestMethod.GET, value = "/policy.xml", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String getDefaultPolicyFile() throws IOException {
        InputStream inputStream;
        final String prefDefaultPolicyUrl = preferencesDao.get(PreferenceKey.DEFAULT_POLICY_URL).getValue();
        if (DSSUtils.isNotEmpty(prefDefaultPolicyUrl)) {
            inputStream = new URL(prefDefaultPolicyUrl).openStream();
        } else {
            inputStream = getClass().getResourceAsStream(ValidationResourceManager.defaultPolicyConstraintsLocation);
        }
        return DSSUtils.toString(inputStream);
    }
}
