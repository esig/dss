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

package eu.europa.ec.markt.dss.applet.controller;

import eu.europa.ec.markt.dss.applet.main.DSSAppletCore;
import eu.europa.ec.markt.dss.applet.model.ActivityModel;
import eu.europa.ec.markt.dss.applet.view.ActivityView;
import eu.europa.ec.markt.dss.applet.wizard.extension.ExtensionWizardController;
import eu.europa.ec.markt.dss.applet.wizard.signature.SignatureWizardController;
import eu.europa.ec.markt.dss.applet.wizard.validation.ValidationWizardController;
import eu.europa.ec.markt.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;

/**
 * 
 * TODO
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ActivityController extends DSSAppletController<ActivityModel> {

    private ActivityView view;

    /**
     * 
     * The default constructor for ActivityController.
     * 
     * @param core
     * @param model
     */
    public ActivityController(final DSSAppletCore core, final ActivityModel model) {
        super(core, model);
        view = new ActivityView(getCore(), this, getModel());
    }

    /**
     * 
     */
    public void display() {
        view.show();
    }

    /**
     * 
     */
    public void startAction() {
        switch (getModel().getAction()) {
        case EXTEND:
            getCore().getController(ExtensionWizardController.class).start();
            break;
        case SIGN:
            getCore().getController(SignatureWizardController.class).start();
            break;
        case VERIFY:
            getCore().getController(ValidationWizardController.class).start();
            break;
        case EDIT_VALIDATION_POLICY:
            getCore().getController(ValidationPolicyWizardController.class).start();
            break;
        }
    }
}
