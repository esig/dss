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
package eu.europa.ec.markt.dss.web.controller.preferences;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import eu.europa.ec.markt.dss.dao.PreferencesDao;
import eu.europa.ec.markt.dss.manager.ProxyPreferenceManager;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.tsl.ReloadableTrustedListCertificateSource;

/**
 * Administration controller
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
@Controller
@RequestMapping(value = "/admin")
public class AdministrationController {
    /**
     * @see eu.europa.ec.markt.dss.validation102853.tsl.ReloadableTrustedListCertificateSource
     */
    @Autowired
    private ReloadableTrustedListCertificateSource reloadableTrustedListCertificateSource;
    /**
     * @see ProxyPreferenceManager
     */
    @Autowired
    @Qualifier("proxyPreferenceManager")
    private ProxyPreferenceManager proxyPreferenceManager;

    /**
     * @see PreferencesDao
     */
    @Autowired
    @Qualifier("preferencesDao")
    private PreferencesDao preferencesDao;

    /**
     * @param model The model attributes
     * @return a view name
     */
    @RequestMapping(value = "/general", method = RequestMethod.GET)
    public String showGlobal(final Model model) {
        model.addAttribute("preferences", preferencesDao.getAll());
        return "admin-general-list";
    }

    /**
     * @param model The model attributes
     * @return a view name
     */
    @RequestMapping(value = "/proxy", method = RequestMethod.GET)
    public String showProxy(final Model model) {
        model.addAttribute("preferences", proxyPreferenceManager.list());
        return "admin-proxy-list";
    }

    /**
     * @param model The model attributes
     * @return a view name
     */
    @RequestMapping(value = "/tsl-info", method = RequestMethod.GET)
    public String showSignature(final Model model) {

        final List<CertificateToken> certificates = reloadableTrustedListCertificateSource.getCertificates();
        model.addAttribute("certs", certificates);
        model.addAttribute("tsls", reloadableTrustedListCertificateSource.getDiagnosticInfo().entrySet());
        return "admin-tsl-info";
    }

}
